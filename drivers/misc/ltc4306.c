/*
 *  ltc4306.c - Linux kernel module for
 * 	Linear Technology LTC4306 4-Channel 2-Wire Bus Multiplexer
 * 	with Capacitance Buffering.
 *
 *  Copyright (c) 2012 Evgeny Kravtsunov <kravtsunov_e@mcst.ru>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/mutex.h>
#include <linux/delay.h>

#define LTC4306_DRV_NAME	"ltc4306"
#define DRIVER_VERSION		"1.0"

#define LTC4306_R0	0x00
#define	LTC4306_R1	0x01
#define LTC4306_R2	0x02
#define LTC4306_R3	0x03

/* Register 0 (R) bits: */

/* Indicates if upstream bus is connected to any downstream busses:
 * 0 - upstream bus disconnected; 1 - upstream bus is connected to
 * one or more downstream busses:
 */
#define LTC4306_R0_DOWNSTREAM_CONN_SHIFT		7
#define LTC4306_R0_DOWNSTREAM_CONN_MASK			\
				(1 << LTC4306_R0_DOWNSTREAM_CONN_SHIFT)

/* Alerts logic states: */
#define LTC4306_R0_ALERT1_LOGIC_STATE_SHIFT		6
#define LTC4306_R0_ALERT1_LOGIC_STATE_MASK		\
				(1 << LTC4306_R0_ALERT1_LOGIC_STATE_SHIFT)
#define LTC4306_R0_ALERT2_LOGIC_STATE_SHIFT		5
#define LTC4306_R0_ALERT2_LOGIC_STATE_MASK		\
				(1 << LTC4306_R0_ALERT2_LOGIC_STATE_SHIFT)
#define LTC4306_R0_ALERT3_LOGIC_STATE_SHIFT		4
#define LTC4306_R0_ALERT3_LOGIC_STATE_MASK		\
				(1 << LTC4306_R0_ALERT3_LOGIC_STATE_SHIFT)
#define LTC4306_R0_ALERT4_LOGIC_STATE_SHIFT		3
#define LTC4306_R0_ALERT4_LOGIC_STATE_MASK		\
				(1 << LTC4306_R0_ALERT4_LOGIC_STATE_SHIFT)

/* Indicates if an attempt to connect to downstream bus failed because 
 * the "Connection Requirement" bit in R2 was low and the downstream bus 
 * was low:
 */
#define LTC4306_R0_FAILED_CONN_SHIFT			2
#define LTC4306_R0_FAILED_CONN_MASK			\
				(1 << LTC4306_R0_FAILED_CONN_SHIFT)

/* Latched bit indicating is a timeout has occured and has not yet been 
 * cleared:
 */
#define LTC4306_R0_LATCHED_TIMEOUT_SHIFT		1
#define LTC4306_R0_LATCHED_TIMEOUT_MASK			\
				(1 << LTC4306_R0_LATCHED_TIMEOUT_SHIFT)

/* Indicates real-time status of Stuck Low Timeout Circuitry: */
#define LTC4306_R0_TIMEOUT_REAL_TIME_SHIFT		0
#define LTC4306_R0_TIMEOUT_REAL_TIME_MASK		\
				(1 << LTC4306_R0_TIMEOUT_REAL_TIME_SHIFT)

/* Register 1 (RW & R) bits: */

/* Activates upstream rise time accelerator currents:
 * 0 - inactive (default);
 * 1 - active 
 */
#define LTC4306_R1_UPSTREAM_ACC_ENABLE_SHIFT		7
#define LTC4306_R1_UPSTREAM_ACC_ENABLE_MASK		\
				(1 << LTC4306_R1_UPSTREAM_ACC_ENABLE_SHIFT)

/* Activates downstream rise time accelerator currents:
 * 0 - inactive (default);
 * 1 - active
 */
#define LTC4306_R1_DOWNSTREAM_ACC_ENABLE_SHIFT		6
#define LTC4306_R1_DOWNSTREAM_ACC_ENABLE_MASK		\
				(1 << LTC4306_R1_DOWNSTREAM_ACC_ENABLE_SHIFT)

/* GPIO1 output driver state, noninverting, default = 1: */
#define LTC4306_R1_GPIO1_OUTPUT_DRIVER_STATE_SHIFT	5
#define LTC4306_R1_GPIO1_OUTPUT_DRIVER_STATE_MASK	\
			    (1 << LTC4306_R1_GPIO1_OUTPUT_DRIVER_STATE_SHIFT)

/* GPIO2 output driver state, noninverting, default = 1: */
#define LTC4306_R1_GPIO2_OUTPUT_DRIVER_STATE_SHIFT	4
#define LTC4306_R1_GPIO2_OUTPUT_DRIVER_STATE_MASK	\
			    (1 << LTC4306_R1_GPIO2_OUTPUT_DRIVER_STATE_SHIFT)

/* Logic state of GPIO1 pin, noninverting: */
#define LTC4306_R1_GPIO1_LOGIC_STATE_SHIFT		1
#define LTC4306_R1_GPIO1_LOGIC_STATE_MASK		\
			    (1 << LTC4306_R1_GPIO1_LOGIC_STATE_SHIFT)

/* Logic state of GPIO2 pin, noninverting: */
#define LTC4306_R1_GPIO2_LOGIC_STATE_SHIFT		0
#define LTC4306_R1_GPIO2_LOGIC_STATE_MASK		\
			    (1 << LTC4306_R1_GPIO2_LOGIC_STATE_SHIFT)

/* Register 2 (RW) bits: */

/* Configures Input/Output mode of GPIO1:
 * 0 - output mode (default);
 * 1 - input mode
 */
#define LTC4306_R2_GPIO1_MODE_CONFIGURE_SHIFT		7
#define LTC4306_R2_GPIO1_MODE_CONFIGURE_MASK		\
			    (1 << LTC4306_R2_GPIO1_MODE_CONFIGURE_SHIFT)

/* Configures Input/Output mode of GPIO2:
 * 0 - output mode (default);
 * 1 - input mode
 */
#define LTC4306_R2_GPIO2_MODE_CONFIGURE_SHIFT		6
#define LTC4306_R2_GPIO2_MODE_CONFIGURE_MASK		\
			    (1 << LTC4306_R2_GPIO2_MODE_CONFIGURE_SHIFT)

/* Sets logic requirements for downstream busses to be connected
 * to upstream bus:
 * 0 - Bus Logic State bits (R3) of busses to be connected must be high;
 * 1 - connect regardless of downstream logic state
 */
#define LTC4306_R2_CONNECTION_REQUIREMENT_SHIFT		5
#define LTC4306_R2_CONNECTION_REQUIREMENT_MASK		\
			    (1 << LTC4306_R2_CONNECTION_REQUIREMENT_SHIFT)

/* Configures GPIO1 Output Mode:
 * 0 - open-drain pull-down (default);
 * 1 - push-pull
 */
#define LTC4306_R2_GPIO1_OUTPUT_MODE_CONFIGURE_SHIFT	4
#define LTC4306_R2_GPIO1_OUTPUT_MODE_CONFIGURE_MASK	\
			(1 << LTC4306_R2_GPIO1_OUTPUT_MODE_CONFIGURE_SHIFT)

/* Configures GPIO2 Output Mode:
 * 0 - open-drain pull-down (default);
 * 1 - push-pull
 */
#define LTC4306_R2_GPIO2_OUTPUT_MODE_CONFIGURE_SHIFT	3
#define LTC4306_R2_GPIO2_OUTPUT_MODE_CONFIGURE_MASK	\
			(1 << LTC4306_R2_GPIO2_OUTPUT_MODE_CONFIGURE_SHIFT)

/* Enable Mass Write Address using (1011 101)b:
 * 0 - disable;
 * 1 - enable (default)
 */
#define LTC4306_R2_MASS_WRITE_ENABLE_SHIFT		2
#define LTC4306_R2_MASS_WRITE_ENABLE_MASK		\
				(1 << LTC4306_R2_MASS_WRITE_ENABLE_SHIFT)

/* Timeout mode: */
#define LTC4306_R2_TIMEOUT_MODE_SHIFT			0
#define LTC4306_R2_TIMEOUT_MODE_MASK			0x3
#define LTC4306_R2_TIMEOUT_DISABLED			0
#define LTC4306_R2_TIMEOUT_30MS				1
#define LTC4306_R2_TIMEOUT_15MS				2
#define LTC4306_R2_TIMEOUT_7d5MS			3

/* Register 3 (RW & R) bits: */

/* Sets and indicates state of FET switches connected to downstream bus 1:
 * 0 - switch open (default);
 * 1 - switch closed
 */
#define LTC4306_R3_BUS1_FET_STATE_SHIFT			7
#define LTC4306_R3_BUS1_FET_STATE_MASK			\
			(1 << LTC4306_R3_BUS1_FET_STATE_SHIFT)

/* Sets and indicates state of FET switches connected to downstream bus 2:
 * 0 - switch open (default);
 * 1 - switch closed
 */
#define LTC4306_R3_BUS2_FET_STATE_SHIFT			6
#define LTC4306_R3_BUS2_FET_STATE_MASK			\
			(1 << LTC4306_R3_BUS2_FET_STATE_SHIFT)

/* Sets and indicates state of FET switches connected to downstream bus 3:
 * 0 - switch open (default);
 * 1 - switch closed
 */
#define LTC4306_R3_BUS3_FET_STATE_SHIFT			5
#define LTC4306_R3_BUS3_FET_STATE_MASK			\
			(1 << LTC4306_R3_BUS3_FET_STATE_SHIFT)

/* Sets and indicates state of FET switches connected to downstream bus 4:
 * 0 - switch open (default);
 * 1 - switch closed
 */
#define LTC4306_R3_BUS4_FET_STATE_SHIFT			4
#define LTC4306_R3_BUS4_FET_STATE_MASK			\
			(1 << LTC4306_R3_BUS4_FET_STATE_SHIFT)

/* Indicates logic state of downstream bus 1; only valid when disconnected
 * from pstream bus:
 * 0 - SDA1, SCL1 or both are below 1V;
 * 1 - SDA1 and SCL1 are both above 1V
 */
#define LTC4306_R3_BUS1_LOGIC_STATE_SHIFT		3
#define LTC4306_R3_BUS1_LOGIC_STATE_MASK		\
			(1 << LTC4306_R3_BUS1_LOGIC_STATE_SHIFT)

/* Indicates logic state of downstream bus 2; only valid when disconnected
 * from pstream bus:
 * 0 - SDA2, SCL2 or both are below 1V;
 * 1 - SDA2 and SCL2 are both above 1V
 */
#define LTC4306_R3_BUS2_LOGIC_STATE_SHIFT		2
#define LTC4306_R3_BUS2_LOGIC_STATE_MASK		\
			(1 << LTC4306_R3_BUS2_LOGIC_STATE_SHIFT)

/* Indicates logic state of downstream bus 3; only valid when disconnected
 * from pstream bus:
 * 0 - SDA3, SCL3 or both are below 1V;
 * 1 - SDA3 and SCL3 are both above 1V
 */
#define LTC4306_R3_BUS3_LOGIC_STATE_SHIFT		1
#define LTC4306_R3_BUS3_LOGIC_STATE_MASK		\
			(1 << LTC4306_R3_BUS3_LOGIC_STATE_SHIFT)

/* Indicates logic state of downstream bus 4; only valid when disconnected
 * from pstream bus:
 * 0 - SDA4, SCL4 or both are below 1V;
 * 1 - SDA4 and SCL4 are both above 1V
 */
#define LTC4306_R3_BUS4_LOGIC_STATE_SHIFT		0
#define LTC4306_R3_BUS4_LOGIC_STATE_MASK		\
			(1 << LTC4306_R3_BUS4_LOGIC_STATE_SHIFT)
/* Common */
#define LTC4306_NUM_CACHABLE_REGS	4

struct ltc4306_data {
	struct i2c_client *client;
	struct mutex lock;
	u8 reg_cache[LTC4306_NUM_CACHABLE_REGS];
};

/*
 * register access helpers
 */

static int __ltc4306_read_reg(struct i2c_client *client,
			       u32 reg, u8 mask, u8 shift)
{
	int v;
	struct ltc4306_data *data = i2c_get_clientdata(client);

	v = i2c_smbus_read_byte_data(client, reg);
	if (v < 0)
		return -ENODEV;

	data->reg_cache[reg] = (u8)v;
	return (data->reg_cache[reg] & mask) >> shift;
}

static int __ltc4306_write_reg(struct i2c_client *client,
				u32 reg, u8 mask, u8 shift, u8 val)
{
	struct ltc4306_data *data = i2c_get_clientdata(client);
	int ret = 0;
	u8 tmp;

	if (reg >= LTC4306_NUM_CACHABLE_REGS)
		return -EINVAL;

	mutex_lock(&data->lock);

	tmp = data->reg_cache[reg];
	tmp &= ~mask;
	tmp |= val << shift;

	ret = i2c_smbus_write_byte_data(client, reg, tmp);
	if (!ret)
		data->reg_cache[reg] = tmp;

	mutex_unlock(&data->lock);
	return ret;
}

/*
 * internally used functions
 */

/* BusX FET State */
static u8 ltc4306_bus_get_FET_state(struct i2c_client *client, int busid)
{
	u8 ret = 0xff;

	switch (busid) {
		case 1:
			ret = __ltc4306_read_reg(client, LTC4306_R3,
					LTC4306_R3_BUS1_FET_STATE_MASK,
					LTC4306_R3_BUS1_FET_STATE_SHIFT);
			break;
		case 2:
			ret = __ltc4306_read_reg(client, LTC4306_R3,
					LTC4306_R3_BUS2_FET_STATE_MASK,
					LTC4306_R3_BUS2_FET_STATE_SHIFT);
			break;
		case 3:
			ret = __ltc4306_read_reg(client, LTC4306_R3,
					LTC4306_R3_BUS3_FET_STATE_MASK,
					LTC4306_R3_BUS3_FET_STATE_SHIFT);
			break;
		case 4:
			ret = __ltc4306_read_reg(client, LTC4306_R3,
					LTC4306_R3_BUS4_FET_STATE_MASK,
					LTC4306_R3_BUS4_FET_STATE_SHIFT);
			break;
		default:
			break;
	}
	return ret;
}

static int ltc4306_bus_set_FET_state(struct i2c_client *client, int busid, 
									u8 val)
{
	int ret = -EINVAL;

	switch (busid) {
		case 1:
			ret = __ltc4306_write_reg(client, LTC4306_R3,
					LTC4306_R3_BUS1_FET_STATE_MASK,
					LTC4306_R3_BUS1_FET_STATE_SHIFT,
					val);
			break;
		case 2:
			ret = __ltc4306_write_reg(client, LTC4306_R3,
					LTC4306_R3_BUS2_FET_STATE_MASK,
					LTC4306_R3_BUS2_FET_STATE_SHIFT,
					val);
			break;
		case 3:
			ret = __ltc4306_write_reg(client, LTC4306_R3,
					LTC4306_R3_BUS3_FET_STATE_MASK,
					LTC4306_R3_BUS3_FET_STATE_SHIFT,
					val);
			break;
		case 4:
			ret = __ltc4306_write_reg(client, LTC4306_R3,
					LTC4306_R3_BUS4_FET_STATE_MASK,
					LTC4306_R3_BUS4_FET_STATE_SHIFT,
					val);
			break;
		default:
			break;
	}
	return ret;
}

/* Connection requirement */
static u8 ltc4306_get_conn_req(struct i2c_client *client)
{
	return __ltc4306_read_reg(client, LTC4306_R2,
				LTC4306_R2_CONNECTION_REQUIREMENT_MASK,
				LTC4306_R2_CONNECTION_REQUIREMENT_SHIFT);
}

static int ltc4306_set_conn_req(struct i2c_client *client, u8 val)
{
	return __ltc4306_write_reg(client, LTC4306_R2,
				LTC4306_R2_CONNECTION_REQUIREMENT_MASK,
				LTC4306_R2_CONNECTION_REQUIREMENT_SHIFT,
				val);
}

/* Mass write */
static u8 ltc4306_get_mass_write(struct i2c_client *client)
{
	return __ltc4306_read_reg(client, LTC4306_R2,
				LTC4306_R2_MASS_WRITE_ENABLE_MASK,
				LTC4306_R2_MASS_WRITE_ENABLE_SHIFT);
}

static int ltc4306_set_mass_write(struct i2c_client *client, u8 val)
{
	return __ltc4306_write_reg(client, LTC4306_R2,
				LTC4306_R2_MASS_WRITE_ENABLE_MASK,
				LTC4306_R2_MASS_WRITE_ENABLE_SHIFT,
				val);
}

/* Timeout */
static u8 ltc4306_get_timeout(struct i2c_client *client)
{
	return __ltc4306_read_reg(client, LTC4306_R2,
				LTC4306_R2_TIMEOUT_MODE_MASK,
				LTC4306_R2_TIMEOUT_MODE_SHIFT);
}

static int ltc4306_set_timeout(struct i2c_client *client, u8 val)
{
	return __ltc4306_write_reg(client, LTC4306_R2,
				LTC4306_R2_TIMEOUT_MODE_MASK,
				LTC4306_R2_TIMEOUT_MODE_SHIFT,
				val);
}

/* Upstream accelerator */
static u8 ltc4306_get_up_accel(struct i2c_client *client)
{
	return __ltc4306_read_reg(client, LTC4306_R1,
				LTC4306_R1_UPSTREAM_ACC_ENABLE_MASK,
				LTC4306_R1_UPSTREAM_ACC_ENABLE_SHIFT);
}

static int ltc4306_set_up_accel(struct i2c_client *client, u8 val)
{
	return __ltc4306_write_reg(client, LTC4306_R1,
				LTC4306_R1_UPSTREAM_ACC_ENABLE_MASK,
				LTC4306_R1_UPSTREAM_ACC_ENABLE_SHIFT,
				val);
}

/* Downstream accelerator */
static u8 ltc4306_get_down_accel(struct i2c_client *client)
{
	return __ltc4306_read_reg(client, LTC4306_R1,
				LTC4306_R1_DOWNSTREAM_ACC_ENABLE_MASK,
				LTC4306_R1_DOWNSTREAM_ACC_ENABLE_SHIFT);
}

static int ltc4306_set_down_accel(struct i2c_client *client, u8 val)
{
	return __ltc4306_write_reg(client, LTC4306_R1,
				LTC4306_R1_DOWNSTREAM_ACC_ENABLE_MASK,
				LTC4306_R1_DOWNSTREAM_ACC_ENABLE_SHIFT,
				val);
}

/*
 * sysfs layer
 */

/* BusX FET State */
static ssize_t ltc4306_bus1_show_FET(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	return sprintf(buf, "%i\n", ltc4306_bus_get_FET_state(client, 1));
}

static ssize_t ltc4306_bus1_store_FET(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	int ret;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	ret = ltc4306_bus_set_FET_state(client, 1, val);
	if (ret < 0)
		return ret;

	return count;
}

static DEVICE_ATTR(bus1_FET, S_IWUSR | S_IRUGO,
		   ltc4306_bus1_show_FET, ltc4306_bus1_store_FET);

static ssize_t ltc4306_bus2_show_FET(struct device *dev,
                                  struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	return sprintf(buf, "%i\n", ltc4306_bus_get_FET_state(client, 2));
}

static ssize_t ltc4306_bus2_store_FET(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	int ret;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	ret = ltc4306_bus_set_FET_state(client, 2, val);
	if (ret < 0)
		return ret;

	return count;
}

static DEVICE_ATTR(bus2_FET, S_IWUSR | S_IRUGO,
		   ltc4306_bus2_show_FET, ltc4306_bus2_store_FET);

static ssize_t ltc4306_bus3_show_FET(struct device *dev,
                                  struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	return sprintf(buf, "%i\n", ltc4306_bus_get_FET_state(client, 3));
}

static ssize_t ltc4306_bus3_store_FET(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	int ret;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	ret = ltc4306_bus_set_FET_state(client, 3, val);
	if (ret < 0)
		return ret;

	return count;
}

static DEVICE_ATTR(bus3_FET, S_IWUSR | S_IRUGO,
		ltc4306_bus3_show_FET, ltc4306_bus3_store_FET);

static ssize_t ltc4306_bus4_show_FET(struct device *dev,
                                  struct device_attribute *attr, char *buf)
{
       struct i2c_client *client = to_i2c_client(dev);
       return sprintf(buf, "%i\n", ltc4306_bus_get_FET_state(client, 4));
}

static ssize_t ltc4306_bus4_store_FET(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	int ret;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	ret = ltc4306_bus_set_FET_state(client, 4, val);
	if (ret < 0)
		return ret;

	return count;
}

static DEVICE_ATTR(bus4_FET, S_IWUSR | S_IRUGO,
		ltc4306_bus4_show_FET, ltc4306_bus4_store_FET);


static ssize_t ltc4306_show_conn_req(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	return sprintf(buf, "%i\n", ltc4306_get_conn_req(client));
}

static ssize_t ltc4306_store_conn_req(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	int ret;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	ret = ltc4306_set_conn_req(client, val);
	if (ret < 0)
		return ret;

	return count;
}

static DEVICE_ATTR(conn_req, S_IWUSR | S_IRUGO,
		ltc4306_show_conn_req, ltc4306_store_conn_req);

static ssize_t ltc4306_show_mass_write(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	return sprintf(buf, "%i\n", ltc4306_get_mass_write(client));
}

static ssize_t ltc4306_store_mass_write(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	int ret;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	ret = ltc4306_set_mass_write(client, val);
	if (ret < 0)
		return ret;

	return count;
}

static DEVICE_ATTR(mass_write, S_IWUSR | S_IRUGO,
		ltc4306_show_mass_write, ltc4306_store_mass_write);

static ssize_t ltc4306_show_timeout(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	return sprintf(buf, "%i\n", ltc4306_get_timeout(client));
}

static ssize_t ltc4306_store_timeout(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	int ret;

	if ((strict_strtoul(buf, 10, &val) < LTC4306_R2_TIMEOUT_DISABLED) || 
					(val > LTC4306_R2_TIMEOUT_7d5MS))
		return -EINVAL;

	ret = ltc4306_set_timeout(client, val);
	if (ret < 0)
		return ret;

	return count;
}

static DEVICE_ATTR(timeout, S_IWUSR | S_IRUGO,
		ltc4306_show_timeout, ltc4306_store_timeout);

/* Read all regs for debug purposes. Can be rewritten with details. */
static ssize_t ltc4306_show_regs(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned char reg0;
	unsigned char reg1;
	unsigned char reg2;
	unsigned char reg3;
	int v;	

	v = i2c_smbus_read_byte_data(client, 0);
	if (v < 0) {
		return -ENODEV;
	}
	reg0 = (unsigned char)v;

	v = i2c_smbus_read_byte_data(client, 1);
        if (v < 0) {
		return -ENODEV;
	}
	reg1 = (unsigned char)v;

	v = i2c_smbus_read_byte_data(client, 2);
	if (v < 0) {
		return -ENODEV;
	}
	reg2 = (unsigned char)v;

	v = i2c_smbus_read_byte_data(client, 3);
	if (v < 0) {
		return -ENODEV;
	}
	reg3 = (unsigned char)v;

	return sprintf(buf, "reg0=0x%x reg1=0x%x reg2=0x%x reg3=0x%x\n", 
						reg0, reg1, reg2, reg3);
}

static DEVICE_ATTR(regs, S_IRUGO, ltc4306_show_regs, NULL);

static ssize_t ltc4306_show_up_accel(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	return sprintf(buf, "%i\n", ltc4306_get_up_accel(client));
}

static ssize_t ltc4306_store_up_accel(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	int ret;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	ret = ltc4306_set_up_accel(client, val);
	if (ret < 0)
		return ret;

	return count;
}

static DEVICE_ATTR(up_accel, S_IWUSR | S_IRUGO,
	ltc4306_show_up_accel, ltc4306_store_up_accel);

static ssize_t ltc4306_show_down_accel(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	return sprintf(buf, "%i\n", ltc4306_get_down_accel(client));
}

static ssize_t ltc4306_store_down_accel(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long val;
	int ret;

	if ((strict_strtoul(buf, 10, &val) < 0) || (val > 1))
		return -EINVAL;

	ret = ltc4306_set_down_accel(client, val);
	if (ret < 0)
		return ret;

	return count;
}

static DEVICE_ATTR(down_accel, S_IWUSR | S_IRUGO,
		ltc4306_show_down_accel, ltc4306_store_down_accel);

/* Reset latched timeout */
static ssize_t ltc4306_store_reset_latched(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	int ret;

	ret = i2c_smbus_write_byte_data(client, LTC4306_R0, 0);

	return ret ? ret : count;
}
static DEVICE_ATTR(reset_latched, S_IWUSR, NULL, ltc4306_store_reset_latched);

static struct attribute *ltc4306_attributes[] = {
	&dev_attr_bus1_FET.attr,
	&dev_attr_bus2_FET.attr,
	&dev_attr_bus3_FET.attr,
	&dev_attr_bus4_FET.attr,
	&dev_attr_conn_req.attr,
	&dev_attr_mass_write.attr,
	&dev_attr_timeout.attr,
	&dev_attr_regs.attr,
	&dev_attr_up_accel.attr,
	&dev_attr_down_accel.attr,
	&dev_attr_reset_latched.attr,
	NULL
};

static const struct attribute_group ltc4306_attr_group = {
	.attrs = ltc4306_attributes,
};

static int ltc4306_init_client(struct i2c_client *client)
{
	struct ltc4306_data *data = i2c_get_clientdata(client);
	int i;

	/* Check all registers are readable,
	 * if one of the reads fails, we consider the init failed. */
	for (i = 0; i < ARRAY_SIZE(data->reg_cache); i++) {
		int v = i2c_smbus_read_byte_data(client, i);
		if (v < 0)
			return -ENODEV;

		data->reg_cache[i] = (u8)v;
	}

	/* set defaults */
	ltc4306_bus_set_FET_state(client, 1, 0);
	ltc4306_bus_set_FET_state(client, 2, 0);
	ltc4306_bus_set_FET_state(client, 3, 0);
	ltc4306_bus_set_FET_state(client, 4, 0);
	ltc4306_set_conn_req(client, 1);
	ltc4306_set_mass_write(client, 0);
	ltc4306_set_timeout(client, LTC4306_R2_TIMEOUT_30MS);

	return 0;
}

/*
 * I2C layer
 */

static int ltc4306_probe(struct i2c_client *client,
				    const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
	struct ltc4306_data *data;
	int err = 0;

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE))
		return -EIO;

	data = kzalloc(sizeof(struct ltc4306_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->client = client;
	i2c_set_clientdata(client, data);
	mutex_init(&data->lock);

	/* initialize the LTC4306 chip */
	err = ltc4306_init_client(client);
	if (err)
		goto exit_kfree;

	/* register sysfs hooks */
	err = sysfs_create_group(&client->dev.kobj, &ltc4306_attr_group);
	if (err)
		goto exit_kfree;

	dev_info(&client->dev, "driver version %s enabled\n", DRIVER_VERSION);
	return 0;

exit_kfree:
	kfree(data);
	return err;
}

static int ltc4306_remove(struct i2c_client *client)
{
	sysfs_remove_group(&client->dev.kobj, &ltc4306_attr_group);
	kfree(i2c_get_clientdata(client));
	return 0;
}

static const struct i2c_device_id ltc4306_id[] = {
	{ "ltc4306", 0 },
	{}
};
MODULE_DEVICE_TABLE(i2c, ltc4306_id);

static struct i2c_driver ltc4306_driver = {
	.driver = {
		.name	= LTC4306_DRV_NAME,
		.owner	= THIS_MODULE,
	},
	.probe	= ltc4306_probe,
	.remove	= ltc4306_remove,
	.id_table = ltc4306_id,
};

static int __init ltc4306_init(void)
{
	return i2c_add_driver(&ltc4306_driver);
}

static void __exit ltc4306_exit(void)
{
	i2c_del_driver(&ltc4306_driver);
}

MODULE_AUTHOR("Evgeny Kravtsunov <kravtsunov_e@mcst.ru>");
MODULE_DESCRIPTION("LTC4306 bus multiplexer driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRIVER_VERSION);

module_init(ltc4306_init);
module_exit(ltc4306_exit);

