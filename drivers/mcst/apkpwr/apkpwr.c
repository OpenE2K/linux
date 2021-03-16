/*
 * apkpwr.c - APKPWR driver
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/i2c.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/power_supply.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/sysfs.h>
#include <linux/gpio_keys.h>
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif /* CONFIG_DEBUG_FS */


#define DRIVER_NAME		"apkpwr"
#define DRIVER_VERSION		"1.0"

#define APKPWR_POWER_SUPPLY	/* Enale POWER_SUPPLY subsystem */
#define APKPWR_GET_DATA_FROM_BATTERY


/*---------------------------------------------------------------------------*/

/* APKPWR registers */
#define APKPWR_REG16_RO_ID		0x00	/* #00,01 */
#define APKPWR_REG16_RW_FLAGS		0x02	/* #02,03 */
#define APKPWR_REG16_RO_BATFLAGS	0x04	/* #04,05 */
#define APKPWR_REG16_RO_ADC_VBAT_I	0x06	/* #06,07 */
#define APKPWR_REG16_RO_ADC_THERM_I	0x08	/* #08,09 */
#define APKPWR_REG16_RO_ADC_VBAT_E	0x0A	/* #0A,0B */
#define APKPWR_REG16_RO_ADC_THERM_E	0x0C	/* #0C,0D */
#define APKPWR_REG16_RO_ADC_V12		0x0E	/* #0E,0F */
#define APKPWR_REG16_RO_ADC_VSYS	0x10	/* #10,11 */
#define APKPWR_REG16_RO_ADC_5VSB	0x12	/* #12,13 */
						/* #14,15 */
#define APKPWR_REG16_RO_LEDS		0x16	/* #16,17 */
/* registers of the accumulators */
#define APKPWR_REG16_RO_UPDATECNT	0x18	/* #18,19 */
/* registers of internal accumulator */
#define APKPWR_REG16_BST_TEMP_I		0x1A	/* Temperature - 0x08 */
#define APKPWR_REG16_BST_VOLT_I		0x1C	/* Voltage - 0x09 */
#define APKPWR_REG16_BST_CURR_I		0x1E	/* Current - 0x0A */
#define APKPWR_REG16_BST_STOFCH_I	0x20	/* RelatStateOfCharge - 0x0D */
#define APKPWR_REG16_BST_REMCAP_I	0x22	/* RemainingCapacity - 0x0F */
#define APKPWR_REG16_BST_FCHCAP_I	0x24	/* FullChargeCapacity - 0x10 */
#define APKPWR_REG16_BST_CHCURR_I	0x26	/* ChargingCurrent - 0x14 */
#define APKPWR_REG16_BST_CHVOLT_I	0x28	/* ChargingVoltage - 0x15 */
#define APKPWR_REG16_BST_STAT_I		0x2A	/* BatteryStatus - 0x16 */
/* registers of external accumulator */
#define APKPWR_REG16_BST_TEMP_E		0x2C	/* Temperature - 0x08 */
#define APKPWR_REG16_BST_VOLT_E		0x2E	/* Voltage - 0x09 */
#define APKPWR_REG16_BST_CURR_E		0x30	/* Current - 0x0A */
#define APKPWR_REG16_BST_STOFCH_E	0x32	/* RelatStateOfCharge - 0x0D */
#define APKPWR_REG16_BST_REMCAP_E	0x34	/* RemainingCapacity - 0x0F */
#define APKPWR_REG16_BST_FCHCAP_E	0x36	/* FullChargeCapacity - 0x10 */
#define APKPWR_REG16_BST_CHCURR_E	0x38	/* ChargingCurrent - 0x14 */
#define APKPWR_REG16_BST_CHVOLT_E	0x3A	/* ChargingVoltage - 0x15 */
#define APKPWR_REG16_BST_STAT_E		0x3C	/* BatteryStatus - 0x16 */

#define APKPWR_REG16_END APKPWR_REG16_BST_STAT_E /* APKPWR_REG16_RO_LEDS */
#define APKPWR_REG16_CNT ((APKPWR_REG16_END / 2) + 1)


/** APKPWR specific bitfields */

/* APKPWR_REG16_RO_ID */
#define MANUFACTURER_ID	0x1502


/* APKPWR_REG16_RW_FLAGS:  FLAG - RO, CMD - RW */
#define FLAG_ACP		0x0001 /* AC adapter ON */
#define CMD_BATSEL		0x0002 /* 0 - select internal battery
					  1 - select external battery */
#define FLAG_FAULT_ICL		0x0004 /* Icharge decreased (Iin > 5A) */


/* APKPWR_REG16_RO_BATFLAGS */
/* - internal battery - */
#define FLAG_ACC_STAT_I		0x0001	/* overtemp2, low bat voltage2 */
#define FLAG_CHARGE_COMPLET_I	0x0002	/* Charge complete (Icharge < 2A-10%) */
#define FLAG_FAULT_SHUTDN_I	0x0004	/* Charging circuit off (overtemp,
					   low bat voltage) */
#define FLAG_FAULT_LOW_VOLT_I	0x0008	/* Low voltage on battery (<16,2V) */
#define FLAG_FAULT_OVERTEMP_I	0x0010	/* Battery overtemp (>45`C or <0`C) */
#define FLAG_FAULT_OVERTEMP2_I	0x0020	/* Battery overtemp (>55`C or <-30`C) */
#define FLAG_FAULT_LOW_VOLT2_I	0x0040	/* Low voltage on battery (<19,3V) */
#define FLAG_ACC_PRESENSE_I	0x0080	/* internal battery present */
/* - external battery - */
#define FLAG_ACC_STAT_E		0x0100	/* overtemp2, low bat voltage2 */
#define FLAG_CHARGE_COMPLET_E	0x0200	/* Charge complete (Icharge < 2A-10%) */
#define FLAG_FAULT_SHUTDN_E	0x0400	/* Charging circuit off (overtemp,
					   low bat voltage) */
#define FLAG_FAULT_LOW_VOLT_E	0x0800	/* Low voltage on battery (<16,2V) */
#define FLAG_FAULT_OVERTEMP_E	0x1000	/* Battery overtemp (>45`C or <0`C) */
#define FLAG_FAULT_OVERTEMP2_E	0x2000	/* Battery overtemp (>55`C or <-30`C) */
#define FLAG_FAULT_LOW_VOLT2_E	0x4000	/* Low voltage on battery (<19,3V) */
#define FLAG_ACC_PRESENSE_E	0x8000	/* internal battery present */


/* APKPWR_REG16_RO_ADC_VBAT_I - battery voltage (from ADC) */
/* APKPWR_REG16_RO_ADC_VBAT_E - battery voltage (from ADC) */
#define ADC_VBAT_MAX		0x03FF /* 0..1023, =1024 - invalid */
#define VBATmV_FROM_ADC(val) ((((val & ADC_VBAT_MAX) * 1000000) / 346883) * 10)
#define CHARGE_MIN	16200 /* TODO: min ? */
#define CHARGE_MAX	25200 /* TODO: max ? */


/* APKPWR_REG16_RO_ADC_THERM_I - battery temp (from ADC) */
/* APKPWR_REG16_RO_ADC_THERM_E - battery temp (from ADC) */
#define ADC_THERM_MAX		0x03FF /* 0..1023, =1024 - invalid */
/* TODO: */
#define TBAToC_FROM_ADC(val) (77126 - (((val & ADC_THERM_MAX) \
			     * 1000000) / 10107))
/*
#define BAT_TEMP_ALERT_MAX	61000
*/


/* APKPWR_REG16_RO_ADC_V12 - output 12V (from ADC) */
#define ADC_V12OUT_MAX		0x03FF /* 0..1023, =1024 - invalid */
#define V12mV_FROM_ADC(val) ((((val & ADC_V12OUT_MAX) * 1000000) / 780487) * 10)


/* APKPWR_REG16_RO_ADC_VSYS - output (27V) system power (from ADC) */
#define ADC_VSYS_MAX		0x03FF /* 0..1023, =1024 - invalid */
#define VSYSmV_FROM_ADC(val) ((((val & ADC_VSYS_MAX) * 1000000) / 346883) * 10)


/* APKPWR_REG16_RO_ADC_5VSB - output 5V (from ADC) */
#define ADC_V5SB_MAX		0x03FF /* 0..1023, =1024 - invalid */
#define V5SBmV_FROM_ADC(val) \
	((((val & ADC_V5SB_MAX) * 1000000) / 18778636) * 100)


/* APKPWR_REG16_RO_LEDS */
#define FLAG_LED_OFF_I		0x0004
#define FLAG_LED_FAULT_I	0x0008	/* red flash short */
#define FLAG_LED_RED_I		0x0010	/* red light */
#define FLAG_LED_RED_PULSE_I	0x0020	/* red flash */
#define FLAG_LED_GREEN_PULSE_I	0x0040	/* green flash */
#define FLAG_LED_GREEN_I	0x0080	/* green light */
#define FLAG_LED_OFF_E		0x0400
#define FLAG_LED_FAULT_E	0x0800	/* red flash short */
#define FLAG_LED_RED_E		0x1000	/* red light */
#define FLAG_LED_RED_PULSE_E	0x2000	/* red flash */
#define FLAG_LED_GREEN_PULSE_E	0x4000	/* green flash */
#define FLAG_LED_GREEN_E	0x8000	/* green light */


/* registers of the accumulators index */
#define BST_REG08_TEMP		0	/* Temperature */
#define BST_REG09_VOLT		1	/* Voltage */
#define BST_REG0A_CURR		2	/* Current */
#define BST_REG0D_STOFCH	3	/* RelatStateOfCharge */
#define BST_REG0F_REMCAP	4	/* RemainingCapacity */
#define BST_REG10_FCHCAP	5	/* FullChargeCapacity */
#define BST_REG14_CHCURR_E	6	/* ChargingCurrent */
#define BST_REG15_CHVOLT_E	7	/* ChargingVoltage */
#define BST_REG16_STAT_E	8	/* BatteryStatus */
#define APKPWR_BSTREGS_CNT (BST_REG16_STAT_E + 1)


/* APKPWR_REG16_BST_TEMP_* */
#define TCFROMmK(val) (((val * 10) - 27315) / 10)	/* `C * 10 */


/*---------------------------------------------------------------------------*/

#ifdef APKPWR_POWER_SUPPLY

/* Battery data
 *
 * power supply monitor class:
 * voltages in uV
 * currents in uA
 * charges in uAh
 * energies in uWh
 * time in seconds
 * temperatures in tenths of degree Celsius
 */
struct apkpwr_bat_data {
	struct power_supply *battery;
	struct power_supply_desc battery_desc;
	int status;	/* power_supply status */
	int health;	/* power_supply health */
	int present;	/* power_supply present */
	int online;	/* power_supply online */
	int level;	/* power_supply capacity_level */
	int voltage;	/* power_supply voltage_now */
	int capacity;	/* power_supply capacity */
	int battemp;	/* power_supply temp */
};

#endif /* APKPWR_POWER_SUPPLY */

/* Client data from accumulators */
struct apkpwr_bat_regs {
	s32 reg[APKPWR_BSTREGS_CNT];
	s32 reg_st[APKPWR_BSTREGS_CNT];
};

/* Client data (each client gets its own) */
struct apkpwr_data {
	struct device *hwmon_dev;
	struct i2c_client *client;
	struct mutex update_lock;

	unsigned long last_updated, rate;	/* in jiffies */
	char valid;	/* zero until following fields are valid */
	/* registers values */
	s32 flags, flags_st;
	s32 batflags, batflags_st;
	s32 vbat_i, vbat_i_st;		/* hwmon in1 */
	s32 therm_i, therm_i_st;	/* hwmon temp1 */
	s32 vbat_e, vbat_e_st;		/* hwmon in2 */
	s32 therm_e, therm_e_st;	/* hwmon temp2 */
	s32 v12, v12_st;		/* hwmon in3 */
	s32 vsys, vsys_st;		/* hwmon in4 */
	s32 v5sb, v5sb_st;		/* hwmon in5 */
	s32 ledflags, ledflags_st;
	s32 updatecnt, updatecnt_st;
	struct apkpwr_bat_regs bat_regs[2];

#ifdef APKPWR_POWER_SUPPLY
	/* Power supply */
	struct apkpwr_bat_data bat_data[2];
#endif /* APKPWR_POWER_SUPPLY */

#ifdef CONFIG_DEBUG_FS
	struct dentry *apkpwr_dbg;
#endif /* CONFIG_DEBUG_FS */
};


/*---------------------------------------------------------------------------*/

/* BUG on linux-l-rt-2.6.33.1/arch/l/kernel/i2c-spi/i2c.c
 * line 328: value |= I2C_TRANS_SIZE(1);
 */
#ifndef USE_READ_WORD

static s32 apkpwr_read_word(struct i2c_client *client, u8 command)
{
	s32 val;
	u16 values;

	/* set address */
	val = i2c_smbus_write_byte(client, command);
	if (val < 0)
		return val;

	/* read 16 bit data */
	val = i2c_smbus_read_i2c_block_data(client, command, 2, (u8 *)&values);
	if (val < 0)
		return val;
	else
		return le16_to_cpu(values);
} /* apkpwr_read_word */

#else

static s32 apkpwr_read_word(struct i2c_client *client, u8 command)
{
	return i2c_smbus_read_word_data(client, command);
} /* apkpwr_read_word */

#endif

#if 0
static s32 apkpwr_read_dump(struct i2c_client *client, u8 command, u8 length,
			   u8 *values)
{
	s32 val;

	/* set address */
	val = i2c_smbus_write_byte(client, command);
	if (val < 0)
		return val;

	/* read data */
	val = i2c_smbus_read_i2c_block_data(client, command, length, values);
	if (val < 0)
		return val;
	else
		return 0;
} /* apkpwr_read_dump */
#endif /* 0 */

#if 0
static s32 apkpwr_write_word(struct i2c_client *client, u8 command, u16 data)
{
	s32 val;
	u16 value = cpu_to_le16(data);

#ifdef DEBUG
	dev_info(&client->adapter->dev,
		 "write_word:  command=0x%02X data=0x%04X\n",
		 command, data);
#endif /* DEBUG */

	/* write 16 bit data */
	val = i2c_smbus_write_block_data(client, command, 2, (u8 *)&value);
	if (val < 0)
		return val;
	else
		return 0;
} /* apkpwr_write_word */
#endif /* 0 */

#if 0
static s32 apkpwr_write_dword(struct i2c_client *client, u8 command, u32 data)
{
	s32 val;
	u32 value = cpu_to_le32(data);

#ifdef DEBUG
	dev_info(&client->adapter->dev,
		 "write_dword: command=0x%02X data=0x%08X\n",
		 command, data);
#endif /* DEBUG */

	/* write 32 bit data */
	val = i2c_smbus_write_block_data(client, command, 4, (u8 *)&value);
	if (val < 0)
		return val;
	else
		return 0;
} /* apkpwr_write_dword */
#endif /* 0 */

#if 0
static s32 apkpwr_write_dump(struct i2c_client *client, u8 command, u8 length,
			    u8 *values)
{
	s32 val;

#ifdef DEBUG
	dev_info(&client->adapter->dev,
		 "write_dump:  command=0x%02X length=%u values: " \
		 "0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n",
		 command, length,
		 *(values + 0), *(values + 1), *(values + 2), *(values + 3),
		 *(values + 4), *(values + 5), *(values + 6), *(values + 7));
#endif /* DEBUG */

	/* write data */
	val = i2c_smbus_write_block_data(client, command, length, values);
	if (val < 0)
		return val;
	else
		return 0;
} /* apkpwr_write_dump */
#endif /* 0 */


#ifdef DEBUG

static void dump_all_regs(struct i2c_client *client)
{
	int i;
	s32 val;
	struct i2c_adapter *adapter = client->adapter;
	struct apkpwr_data *data = i2c_get_clientdata(client);

	mutex_lock(&data->update_lock);
	for (i = APKPWR_REG16_RO_ID; i <= APKPWR_REG16_END; i += 2) {
		val = apkpwr_read_word(client, i);
		if (val < 0) {
			dev_err(&adapter->dev,
				"apkpwr: reg16[%02d] - read_error (%d)\n",
				i, val);
		} else {
			dev_dbg(&adapter->dev,
				"apkpwr: reg16[%02d] = 0x%04x (%u)\n",
				i, (u16)val, (u16)val);
		}
	}
	mutex_unlock(&data->update_lock);
} /* dump_all_regs */

#endif /* DEBUG */


#define APKPWR_UPDATE_FLAGS(REG, VAL, VAL_ST) \
do { \
	data->VAL_ST = apkpwr_read_word(client, (REG)); \
	if (data->VAL_ST < 0) \
		data->VAL = 0; \
	else \
		data->VAL = data->VAL_ST; \
} while (0)

#define APKPWR_UPDATE_VAL(REG, VAL, VAL_ST, MAX) \
do { \
	data->VAL_ST = apkpwr_read_word(client, (REG)); \
	if (data->VAL_ST < 0) \
		data->VAL = (MAX) + 1; \
	else \
		data->VAL = data->VAL_ST; \
} while (0)


static void apkpwr_update_data(struct apkpwr_data *data)
{
	int i;
	struct i2c_client *client = data->client;

	if (!client)
		return;

	mutex_lock(&data->update_lock);

	if (time_after(jiffies, data->last_updated + data->rate) ||
	    !data->valid) {
		/* read all regs */

		APKPWR_UPDATE_FLAGS(APKPWR_REG16_RW_FLAGS,
				    flags, flags_st);
		APKPWR_UPDATE_FLAGS(APKPWR_REG16_RO_BATFLAGS,
				    batflags, batflags_st);
		APKPWR_UPDATE_FLAGS(APKPWR_REG16_RO_LEDS,
				    ledflags, ledflags_st);
		APKPWR_UPDATE_FLAGS(APKPWR_REG16_RO_UPDATECNT,
				    updatecnt, updatecnt_st);

		APKPWR_UPDATE_VAL(APKPWR_REG16_RO_ADC_VBAT_I,
				  vbat_i, vbat_i_st, ADC_VBAT_MAX);
		APKPWR_UPDATE_VAL(APKPWR_REG16_RO_ADC_THERM_I,
				  therm_i, therm_i_st, ADC_THERM_MAX);
		APKPWR_UPDATE_VAL(APKPWR_REG16_RO_ADC_VBAT_E,
				  vbat_e, vbat_e_st, ADC_VBAT_MAX);
		APKPWR_UPDATE_VAL(APKPWR_REG16_RO_ADC_THERM_E,
				  therm_e, therm_e_st, ADC_THERM_MAX);
		APKPWR_UPDATE_VAL(APKPWR_REG16_RO_ADC_V12,
				  v12, v12_st, ADC_V12OUT_MAX);
		APKPWR_UPDATE_VAL(APKPWR_REG16_RO_ADC_VSYS,
				  vsys, vsys_st, ADC_VSYS_MAX);
		APKPWR_UPDATE_VAL(APKPWR_REG16_RO_ADC_5VSB,
				  v5sb, v5sb_st, ADC_V5SB_MAX);

		for (i = 0; i < APKPWR_BSTREGS_CNT; i++) {
			APKPWR_UPDATE_FLAGS(APKPWR_REG16_BST_TEMP_I + (i << 1),
					bat_regs[0].reg[i],
					bat_regs[0].reg_st[i]);
		}
		for (i = 0; i < APKPWR_BSTREGS_CNT; i++) {
			APKPWR_UPDATE_FLAGS(APKPWR_REG16_BST_TEMP_E + (i << 1),
					bat_regs[1].reg[i],
					bat_regs[1].reg_st[i]);
		}

#ifdef APKPWR_POWER_SUPPLY

		/* State Of Charge - TODO */
		if ((data->batflags_st < 0) || (data->flags_st < 0))
			data->bat_data[0].status =
				POWER_SUPPLY_STATUS_UNKNOWN;
		else if (data->batflags & FLAG_FAULT_SHUTDN_I)
			data->bat_data[0].status =
				POWER_SUPPLY_STATUS_NOT_CHARGING;
		else if (data->batflags & FLAG_CHARGE_COMPLET_I)
			data->bat_data[0].status =
				POWER_SUPPLY_STATUS_FULL;
		else if (data->flags & FLAG_ACP)
			data->bat_data[0].status =
				POWER_SUPPLY_STATUS_CHARGING;
		else
			data->bat_data[0].status =
				POWER_SUPPLY_STATUS_DISCHARGING;

		/* HEALTH - TODO */
		if ((data->batflags_st < 0) || (data->flags_st < 0) ||
		    (data->ledflags_st < 0))
			data->bat_data[0].health =
				POWER_SUPPLY_HEALTH_UNKNOWN;
		else if (data->batflags & FLAG_FAULT_OVERTEMP_I)
			data->bat_data[0].health =
				POWER_SUPPLY_HEALTH_OVERHEAT;
		else if (data->flags & FLAG_FAULT_LOW_VOLT2_I)
			data->bat_data[0].health =
				POWER_SUPPLY_HEALTH_OVERVOLTAGE;
		else if (data->batflags & FLAG_FAULT_LOW_VOLT_I)
			data->bat_data[0].health =
				POWER_SUPPLY_HEALTH_DEAD;
		else if (data->ledflags & FLAG_LED_FAULT_I)
			data->bat_data[0].health =
				POWER_SUPPLY_HEALTH_DEAD;
		else if (data->batflags & FLAG_FAULT_SHUTDN_I)
			data->bat_data[0].health =
				POWER_SUPPLY_HEALTH_UNSPEC_FAILURE;
		else
			data->bat_data[0].health =
				POWER_SUPPLY_HEALTH_GOOD;

		/* present - Ok */
#ifdef APKPWR_GET_DATA_FROM_BATTERY
		if (data->updatecnt_st < 0) {
			data->bat_data[0].present = 0;
			data->bat_data[1].present = 0;
		} else {
			if (data->updatecnt & 0x00FF)
				data->bat_data[0].present = 1;
			else
				data->bat_data[0].present = 0;
			if (data->updatecnt & 0xFF00)
				data->bat_data[1].present = 1;
			else
				data->bat_data[1].present = 0;
		}
#else
		if (data->batflags_st < 0) {
			data->bat_data[0].present = 0;
		} else {
			if (data->batflags & FLAG_ACC_PRESENSE_I) {
				data->bat_data[0].present = 1;
			} else {
				data->bat_data[0].present = 0;
			}
		}
#endif /* APKPWR_GET_DATA_FROM_BATTERY */

		/* AC Connect - Ok */
		if (data->flags_st < 0) {
			data->bat_data[0].online = 0;
			data->bat_data[1].online = 0;
		} else {
			data->bat_data[0].online =
				(data->flags & FLAG_ACP) ? 1 : 0;
			data->bat_data[1].online =
				(data->flags & FLAG_ACP) ? 1 : 0;
		}

		/* CAPACITY_LEVEL - TODO */
		if ((data->batflags_st < 0) || (data->ledflags_st < 0))
			data->bat_data[0].level =
				POWER_SUPPLY_CAPACITY_LEVEL_UNKNOWN;
		else if (data->batflags & FLAG_CHARGE_COMPLET_I)
			data->bat_data[0].level =
				POWER_SUPPLY_CAPACITY_LEVEL_FULL;
		else if (data->ledflags & FLAG_LED_GREEN_I)
			data->bat_data[0].level =
				POWER_SUPPLY_CAPACITY_LEVEL_HIGH;
		else if (data->ledflags & FLAG_LED_GREEN_PULSE_I)
			data->bat_data[0].level =
				POWER_SUPPLY_CAPACITY_LEVEL_NORMAL;
		else if (data->ledflags & FLAG_LED_RED_PULSE_I)
			data->bat_data[0].level =
				POWER_SUPPLY_CAPACITY_LEVEL_LOW;
		else if (data->ledflags & FLAG_LED_RED_I)
			data->bat_data[0].level =
				POWER_SUPPLY_CAPACITY_LEVEL_CRITICAL;
		else if (data->ledflags & FLAG_LED_FAULT_I)
			data->bat_data[0].level =
				POWER_SUPPLY_CAPACITY_LEVEL_UNKNOWN;
		else
			data->bat_data[0].level =
				POWER_SUPPLY_CAPACITY_LEVEL_UNKNOWN;

		/* VOLTAGE_NOW - Ok */
#ifdef APKPWR_GET_DATA_FROM_BATTERY
		if (data->bat_regs[0].reg_st[BST_REG09_VOLT] < 0) {
			data->bat_data[0].voltage = 0;
		} else {
			data->bat_data[0].voltage = \
				data->bat_regs[0].reg[BST_REG09_VOLT] * 1000;
		}
		if (data->bat_regs[1].reg_st[BST_REG09_VOLT] < 0) {
			data->bat_data[1].voltage = 0;
		} else {
			data->bat_data[1].voltage = \
				data->bat_regs[1].reg[BST_REG09_VOLT] * 1000;
		}
#else
		if (data->vbat_i_st < 0)
			data->bat_data[0].voltage = 0;
		else
			data->bat_data[0].voltage =
				VBATmV_FROM_ADC(data->vbat_i) * 1000;
#endif /* APKPWR_GET_DATA_FROM_BATTERY */

		/* CAPACITY in percents - Ok */
#ifdef APKPWR_GET_DATA_FROM_BATTERY
		if (data->bat_regs[0].reg_st[BST_REG0D_STOFCH] < 0) {
			data->bat_data[0].capacity = 0;
		} else {
			data->bat_data[0].capacity = \
				data->bat_regs[0].reg[BST_REG0D_STOFCH];
		}
		if (data->bat_regs[1].reg_st[BST_REG0D_STOFCH] < 0) {
			data->bat_data[1].capacity = 0;
		} else {
			data->bat_data[1].capacity = \
				data->bat_regs[1].reg[BST_REG0D_STOFCH];
		}
#else
		if (data->vbat_i_st < 0) {
			data->bat_data[0].capacity = 0;
		} else {
			int val;
			val = VBATmV_FROM_ADC(data->vbat_i);
			val = 100 - ((100 * (CHARGE_MAX - val)) \
				/ (CHARGE_MAX - CHARGE_MIN));
			if (val < 0)
				val = 0;
			if (val > 100)
				val = 100;
			data->bat_data[0].capacity = val;
		}
#endif /* APKPWR_GET_DATA_FROM_BATTERY */

		/* TEMP - Ok */
#ifdef APKPWR_GET_DATA_FROM_BATTERY
		if (data->bat_regs[0].reg_st[BST_REG08_TEMP] < 0) {
			data->bat_data[0].battemp = 0;
		} else {
			data->bat_data[0].battemp = \
				TCFROMmK(data->bat_regs[0].reg[BST_REG08_TEMP]);
		}
		if (data->bat_regs[1].reg_st[BST_REG08_TEMP] < 0) {
			data->bat_data[1].battemp = 0;
		} else {
			data->bat_data[1].battemp = \
				TCFROMmK(data->bat_regs[1].reg[BST_REG08_TEMP]);
		}
#else
		if (data->therm_i_st < 0) {
			data->bat_data[0].battemp = 0;
		} else {
			int val;
			val = TBAToC_FROM_ADC(data->therm_i);
			data->bat_data[0].battemp = (val / 100);
		}
#endif /* APKPWR_GET_DATA_FROM_BATTERY */

#endif /* APKPWR_POWER_SUPPLY */


		/* update status */
		data->last_updated = jiffies;
		data->valid = 1;
	}

	mutex_unlock(&data->update_lock);
} /* apkpwr_update_data */


/*---------------------------------------------------------------------------*/
/* Debugfs part                                                              */
/* Usage: mount -t debugfs none /sys/kernel/debug                            */
/*---------------------------------------------------------------------------*/

#ifdef CONFIG_DEBUG_FS

const char *apkpwr_dbg_regs_name[APKPWR_REG16_CNT] = {
	"ID",
	"RW_FLAGS",
	"BATFLAGS",
	"ADC_VBAT_I",
	"ADC_THERM_I",
	"ADC_VBAT_E",
	"ADC_THERM_E",
	"ADC_V12",
	"ADC_VSYS",
	"ADC_5VSB",
	"",
	"LEDS",
	"UPDATECNT",
	"BST_TEMP_I(08)",
	"BST_VOLT_I(09)",
	"BST_CURR_I(0A)",
	"BST_STOFCH_I(0D)",
	"BST_REMCAP_I(0F)",
	"BST_FCHCAP_I(10)",
	"BST_CHCURR_I(14)",
	"BST_CHVOLT_I(15)",
	"BST_STAT_I(16)",
	"BST_TEMP_E(08)",
	"BST_VOLT_E(09)",
	"BST_CURR_E(0A)",
	"BST_STOFCH_E(0D)",
	"BST_REMCAP_E(0F)",
	"BST_FCHCAP_E(10)",
	"BST_CHCURR_E(14)",
	"BST_CHVOLT_E(15)",
	"BST_STAT_E(16)",
};

static char apkpwr_dbg_regs_buf[PAGE_SIZE] = "";

/**
 * apkpwr_dbg_regs_read - read for regs datum
 * @filp: the opened file
 * @buffer: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 **/
static ssize_t apkpwr_dbg_regs_read(struct file *filp, char __user *buffer,
				    size_t count, loff_t *ppos)
{
	int i;
	s32 val;
	char *buf = apkpwr_dbg_regs_buf;
	int offs = 0;
	struct apkpwr_data *data = filp->private_data;
	struct i2c_client *client = data->client;
	struct i2c_adapter *adapter = client->adapter;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	mutex_lock(&data->update_lock);
	for (i = 0; i < APKPWR_REG16_CNT; i++) {
		val = apkpwr_read_word(client, i << 1);
		if (val < 0) {
			dev_err(&adapter->dev,
				"apkpwr: reg16[%02d] - read_error (%d)\n",
				i, val);
		} else {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "reg16[%02d] = 0x%04x (%5u) - %s\n",
					  i, (u16)val, (u16)val,
					  apkpwr_dbg_regs_name[i]);
		}
	}
	mutex_unlock(&data->update_lock);

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	return simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));
} /* apkpwr_dbg_regs_read */

static const struct file_operations apkpwr_dbg_regs_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = apkpwr_dbg_regs_read,
	/*.write = apkpwr_dbg_regs_write,*/
};

/* /sys/kernel/debug/apkpwr */
static struct dentry *apkpwr_dbg_root;

/**
 * apkpwr_dbgfs_init - setup the debugfs directory
 **/
void apkpwr_dbgfs_init(struct i2c_client *client)
{
	struct dentry *pfile;
	const char *name = client->name;
	struct apkpwr_data *data = i2c_get_clientdata(client);

	data->apkpwr_dbg = debugfs_create_dir(name, apkpwr_dbg_root);
	if (data->apkpwr_dbg) {
		/* regs */
		pfile = debugfs_create_file("regs", 0600,
					    data->apkpwr_dbg, data,
					    &apkpwr_dbg_regs_fops);
		if (!pfile) {
			dev_err(&client->dev,
				"debugfs regs for %s failed\n", name);
		}
	} else {
		dev_err(&client->dev, "debugfs entry for %s failed\n", name);
	}
} /* apkpwr_dbgfs_init */

/**
 * apkpwr_dbgfs_exit - clear out debugfs entries
 **/
void apkpwr_dbgfs_exit(struct i2c_client *client)
{
	struct apkpwr_data *data = i2c_get_clientdata(client);

	if (data->apkpwr_dbg)
		debugfs_remove_recursive(data->apkpwr_dbg);
	data->apkpwr_dbg = NULL;
} /* apkpwr_dbgfs_exit */

#endif /* CONFIG_DEBUG_FS */


/*---------------------------------------------------------------------------*/
/* HWMON                                                                     */
/*---------------------------------------------------------------------------*/

static struct apkpwr_data *apkpwr_update_device(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct apkpwr_data *data = i2c_get_clientdata(client);

	apkpwr_update_data(data);

	return data;
} /* apkpwr_update_device */


#define APKPWR_FUNC_SHOWLABEL(NAME, LABEL) \
static ssize_t NAME(struct device *dev, struct device_attribute *attr, \
		    char *buf) \
{ \
	return snprintf(buf, PAGE_SIZE - 1, "%s\n", LABEL); \
}

#define APKPWR_FUNC_SHOWRAW(NAME, VAR) \
static ssize_t NAME(struct device *dev, struct device_attribute *attr, \
		    char *buf) \
{ \
	struct apkpwr_data *data = apkpwr_update_device(dev); \
	return snprintf(buf, PAGE_SIZE - 1, "0x%04X\n", data->VAR); \
}


/* APKPWR_REG16_RW_FLAGS */
static ssize_t show_flags(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct apkpwr_data *data = apkpwr_update_device(dev);

	/* attr specific */
	if (data->flags_st < 0) {
		snprintf(buf, PAGE_SIZE - 1, "error\n");
	} else {
		snprintf(buf, PAGE_SIZE - 1,
		     "%sACP\n"
		     "%sBATSEL\n"
		     "%sFAULT_ICL\n",
		     (data->flags & FLAG_ACP) ? "+" : "-",
		     (data->flags & CMD_BATSEL) ? "+" : "-",
		     (data->flags & FLAG_FAULT_ICL) ? "+" : "-");
	}

	return strlen(buf);
} /* show_flags */

/* APKPWR_REG16_RO_BATFLAGS */
static ssize_t show_batflags(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct apkpwr_data *data = apkpwr_update_device(dev);

	/* attr specific */
	if (data->batflags_st < 0) {
		snprintf(buf, PAGE_SIZE - 1, "error\n");
	} else {
		snprintf(buf, PAGE_SIZE - 1,
		     "%sI_ACC_STAT\n"
		     "%sI_CHARGE_COMPLET\n"
		     "%sI_FAULT_SHUTDN\n"
		     "%sI_FAULT_LOW_VOLT\n"
		     "%sI_FAULT_OVERTEMP\n"
		     "%sI_FAULT_OVERTEMP2\n"
		     "%sI_FAULT_LOW_VOLT2\n"
		     "%sI_ACC_PRESENSE\n"
		     "%sE_ACC_STAT\n"
		     "%sE_CHARGE_COMPLET\n"
		     "%sE_FAULT_SHUTDN\n"
		     "%sE_FAULT_LOW_VOLT\n"
		     "%sE_FAULT_OVERTEMP\n"
		     "%sE_FAULT_OVERTEMP2\n"
		     "%sE_FAULT_LOW_VOLT2\n"
		     "%sE_ACC_PRESENSE\n",
		     (data->batflags & FLAG_ACC_STAT_I) ? "+" : "-",
		     (data->batflags & FLAG_CHARGE_COMPLET_I) ? "+" : "-",
		     (data->batflags & FLAG_FAULT_SHUTDN_I) ? "+" : "-",
		     (data->batflags & FLAG_FAULT_LOW_VOLT_I) ? "+" : "-",
		     (data->batflags & FLAG_FAULT_OVERTEMP_I) ? "+" : "-",
		     (data->batflags & FLAG_FAULT_OVERTEMP2_I) ? "+" : "-",
		     (data->batflags & FLAG_FAULT_LOW_VOLT2_I) ? "+" : "-",
		     (data->batflags & FLAG_ACC_PRESENSE_I) ? "+" : "-",
		     (data->batflags & FLAG_ACC_STAT_E) ? "+" : "-",
		     (data->batflags & FLAG_CHARGE_COMPLET_E) ? "+" : "-",
		     (data->batflags & FLAG_FAULT_SHUTDN_E) ? "+" : "-",
		     (data->batflags & FLAG_FAULT_LOW_VOLT_E) ? "+" : "-",
		     (data->batflags & FLAG_FAULT_OVERTEMP_E) ? "+" : "-",
		     (data->batflags & FLAG_FAULT_OVERTEMP2_E) ? "+" : "-",
		     (data->batflags & FLAG_FAULT_LOW_VOLT2_E) ? "+" : "-",
		     (data->batflags & FLAG_ACC_PRESENSE_E) ? "+" : "-");
	}

	return strlen(buf);
} /* show_batflags */

/* APKPWR_REG16_RO_LEDS */
static ssize_t show_ledflags(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct apkpwr_data *data = apkpwr_update_device(dev);

	/* attr specific */
	if (data->ledflags_st < 0) {
		snprintf(buf, PAGE_SIZE - 1, "error\n");
	} else {
		snprintf(buf, PAGE_SIZE - 1,
		     "%sI_LED_FAULT\n"
		     "%sI_LED_RED\n"
		     "%sI_LED_RED_PULSE\n"
		     "%sI_LED_GREEN_PULSE\n"
		     "%sI_LED_GREEN\n"
		     "%sE_LED_FAULT\n"
		     "%sE_LED_RED\n"
		     "%sE_LED_RED_PULSE\n"
		     "%sE_LED_GREEN_PULSE\n"
		     "%sE_LED_GREEN\n",
		     (data->ledflags & FLAG_LED_FAULT_I) ? "+" : "-",
		     (data->ledflags & FLAG_LED_RED_I) ? "+" : "-",
		     (data->ledflags & FLAG_LED_RED_PULSE_I) ? "+" : "-",
		     (data->ledflags & FLAG_LED_GREEN_PULSE_I) ? "+" : "-",
		     (data->ledflags & FLAG_LED_GREEN_I) ? "+" : "-",
		     (data->ledflags & FLAG_LED_FAULT_E) ? "+" : "-",
		     (data->ledflags & FLAG_LED_RED_E) ? "+" : "-",
		     (data->ledflags & FLAG_LED_RED_PULSE_E) ? "+" : "-",
		     (data->ledflags & FLAG_LED_GREEN_PULSE_E) ? "+" : "-",
		     (data->ledflags & FLAG_LED_GREEN_E) ? "+" : "-");
	}

	return strlen(buf);
} /* show_ledflags */

/* APKPWR_REG16_RO_ADC_VBAT_I */
static ssize_t show_vbat_i(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	struct apkpwr_data *data = apkpwr_update_device(dev);

	/* attr specific */
	if (data->vbat_i_st < 0) {
		snprintf(buf, PAGE_SIZE - 1, "error\n");
	} else {
		if (data->vbat_i >= ADC_VBAT_MAX) {
			snprintf(buf, PAGE_SIZE - 1, "Unknown\n");
		} else {
			snprintf(buf, PAGE_SIZE - 1, "%d\n",
				 VBATmV_FROM_ADC(data->vbat_i));
		}
	}

	return strlen(buf);
} /* show_vbat_i */

/* APKPWR_REG16_RO_ADC_THERM_I */
static ssize_t show_therm_i(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct apkpwr_data *data = apkpwr_update_device(dev);

	/* attr specific */
	if (data->therm_i_st < 0) {
		snprintf(buf, PAGE_SIZE - 1, "error\n");
	} else {
		if (data->therm_i >= ADC_THERM_MAX) {
			snprintf(buf, PAGE_SIZE - 1, "Unknown\n");
		} else {
			snprintf(buf, PAGE_SIZE - 1, "%d\n",
				TBAToC_FROM_ADC(data->therm_i));
		}
	}

	return strlen(buf);
} /* show_therm_i */

/* APKPWR_REG16_RO_ADC_VBAT_E */
static ssize_t show_vbat_e(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	struct apkpwr_data *data = apkpwr_update_device(dev);

	/* attr specific */
	if (data->vbat_e_st < 0) {
		snprintf(buf, PAGE_SIZE - 1, "error\n");
	} else {
		if (data->vbat_e >= ADC_VBAT_MAX) {
			snprintf(buf, PAGE_SIZE - 1, "Unknown\n");
		} else {
			snprintf(buf, PAGE_SIZE - 1, "%d\n",
				 VBATmV_FROM_ADC(data->vbat_e));
		}
	}

	return strlen(buf);
} /* show_vbat_e */

/* APKPWR_REG16_RO_ADC_THERM_E */
static ssize_t show_therm_e(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct apkpwr_data *data = apkpwr_update_device(dev);

	/* attr specific */
	if (data->therm_e_st < 0) {
		snprintf(buf, PAGE_SIZE - 1, "error\n");
	} else {
		if (data->therm_e >= ADC_THERM_MAX) {
			snprintf(buf, PAGE_SIZE - 1, "Unknown\n");
		} else {
			snprintf(buf, PAGE_SIZE - 1, "%d\n",
				TBAToC_FROM_ADC(data->therm_e));
		}
	}

	return strlen(buf);
} /* show_therm_e */

/* APKPWR_REG16_RO_ADC_V12 */
static ssize_t show_v12(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	struct apkpwr_data *data = apkpwr_update_device(dev);

	/* attr specific */
	if (data->v12_st < 0) {
		snprintf(buf, PAGE_SIZE - 1, "error\n");
	} else {
		if (data->v12 >= ADC_V12OUT_MAX) {
			snprintf(buf, PAGE_SIZE - 1, "Unknown\n");
		} else {
			snprintf(buf, PAGE_SIZE - 1, "%d\n",
				 V12mV_FROM_ADC(data->v12));
		}
	}

	return strlen(buf);
} /* show_v12 */

/* APKPWR_REG16_RO_ADC_VSYS */
static ssize_t show_vsys(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct apkpwr_data *data = apkpwr_update_device(dev);

	/* attr specific */
	if (data->vsys_st < 0) {
		snprintf(buf, PAGE_SIZE - 1, "error\n");
	} else {
		if (data->vsys >= ADC_VSYS_MAX) {
			snprintf(buf, PAGE_SIZE - 1, "Unknown\n");
		} else {
			snprintf(buf, PAGE_SIZE - 1, "%d\n",
				 VSYSmV_FROM_ADC(data->vsys));
		}
	}

	return strlen(buf);
} /* show_vsys */

/* APKPWR_REG16_RO_ADC_5VSB */
static ssize_t show_v5sb(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct apkpwr_data *data = apkpwr_update_device(dev);

	/* attr specific */
	if (data->v5sb_st < 0) {
		snprintf(buf, PAGE_SIZE - 1, "error\n");
	} else {
		if (data->v5sb >= ADC_V5SB_MAX) {
			snprintf(buf, PAGE_SIZE - 1, "Unknown\n");
		} else {
			snprintf(buf, PAGE_SIZE - 1, "%d\n",
				 V5SBmV_FROM_ADC(data->v5sb));
		}
	}

	return strlen(buf);
} /* show_v5sb */


APKPWR_FUNC_SHOWRAW(show_flags_raw, flags)
APKPWR_FUNC_SHOWRAW(show_batflags_raw, batflags)
APKPWR_FUNC_SHOWRAW(show_ledflags_raw, ledflags)
APKPWR_FUNC_SHOWRAW(show_vbat_i_raw, vbat_i)
APKPWR_FUNC_SHOWRAW(show_therm_i_raw, therm_i)
APKPWR_FUNC_SHOWRAW(show_vbat_e_raw, vbat_e)
APKPWR_FUNC_SHOWRAW(show_therm_e_raw, therm_e)
APKPWR_FUNC_SHOWRAW(show_v12_raw, v12)
APKPWR_FUNC_SHOWRAW(show_vsys_raw, vsys)
APKPWR_FUNC_SHOWRAW(show_v5sb_raw, v5sb)

APKPWR_FUNC_SHOWLABEL(show_vbat_i_l, "Internal Battery Voltage")
APKPWR_FUNC_SHOWLABEL(show_therm_i_l, "Internal Battery Temperature")
APKPWR_FUNC_SHOWLABEL(show_vbat_e_l, "External Battery Voltage")
APKPWR_FUNC_SHOWLABEL(show_therm_e_l, "External Battery Temperature")
APKPWR_FUNC_SHOWLABEL(show_v12_l, "+12 Voltage")
APKPWR_FUNC_SHOWLABEL(show_vsys_l, "System Voltage")
APKPWR_FUNC_SHOWLABEL(show_v5sb_l, "+5 SB Voltage")


static DEVICE_ATTR(flags,        S_IRUGO, show_flags,        NULL);
static DEVICE_ATTR(flags_raw,    S_IRUGO, show_flags_raw,    NULL);
static DEVICE_ATTR(batflags,     S_IRUGO, show_batflags,     NULL);
static DEVICE_ATTR(batflags_raw, S_IRUGO, show_batflags_raw, NULL);
static DEVICE_ATTR(ledflags,     S_IRUGO, show_ledflags,     NULL);
static DEVICE_ATTR(ledflags_raw, S_IRUGO, show_ledflags_raw, NULL);
static DEVICE_ATTR(in1_input,   S_IRUGO, show_vbat_i,      NULL);
static DEVICE_ATTR(in1_raw,     S_IRUGO, show_vbat_i_raw,  NULL);
static DEVICE_ATTR(in1_label,   S_IRUGO, show_vbat_i_l,    NULL);
static DEVICE_ATTR(temp1_input, S_IRUGO, show_therm_i,     NULL);
static DEVICE_ATTR(temp1_raw,   S_IRUGO, show_therm_i_raw, NULL);
static DEVICE_ATTR(temp1_label, S_IRUGO, show_therm_i_l,   NULL);
static DEVICE_ATTR(in2_input,   S_IRUGO, show_vbat_e,      NULL);
static DEVICE_ATTR(in2_raw,     S_IRUGO, show_vbat_e_raw,  NULL);
static DEVICE_ATTR(in2_label,   S_IRUGO, show_vbat_e_l,    NULL);
static DEVICE_ATTR(temp2_input, S_IRUGO, show_therm_e,     NULL);
static DEVICE_ATTR(temp2_raw,   S_IRUGO, show_therm_e_raw, NULL);
static DEVICE_ATTR(temp2_label, S_IRUGO, show_therm_e_l,   NULL);
static DEVICE_ATTR(in3_input, S_IRUGO, show_v12,      NULL);
static DEVICE_ATTR(in3_raw,   S_IRUGO, show_v12_raw,  NULL);
static DEVICE_ATTR(in3_label, S_IRUGO, show_v12_l,    NULL);
static DEVICE_ATTR(in4_input, S_IRUGO, show_vsys,     NULL);
static DEVICE_ATTR(in4_raw,   S_IRUGO, show_vsys_raw, NULL);
static DEVICE_ATTR(in4_label, S_IRUGO, show_vsys_l,   NULL);
static DEVICE_ATTR(in5_input, S_IRUGO, show_v5sb,     NULL);
static DEVICE_ATTR(in5_raw,   S_IRUGO, show_v5sb_raw, NULL);
static DEVICE_ATTR(in5_label, S_IRUGO, show_v5sb_l,   NULL);

static struct attribute *apkpwr_attributes[] = {
	&dev_attr_flags.attr,
	&dev_attr_flags_raw.attr,
	&dev_attr_batflags.attr,
	&dev_attr_batflags_raw.attr,
	&dev_attr_ledflags.attr,
	&dev_attr_ledflags_raw.attr,
	&dev_attr_in1_input.attr,
	&dev_attr_in1_raw.attr,
	&dev_attr_in1_label.attr,
	&dev_attr_temp1_input.attr,
	&dev_attr_temp1_raw.attr,
	&dev_attr_temp1_label.attr,
	&dev_attr_in2_input.attr,
	&dev_attr_in2_raw.attr,
	&dev_attr_in2_label.attr,
	&dev_attr_temp2_input.attr,
	&dev_attr_temp2_raw.attr,
	&dev_attr_temp2_label.attr,
	&dev_attr_in3_input.attr,
	&dev_attr_in3_raw.attr,
	&dev_attr_in3_label.attr,
	&dev_attr_in4_input.attr,
	&dev_attr_in4_raw.attr,
	&dev_attr_in4_label.attr,
	&dev_attr_in5_input.attr,
	&dev_attr_in5_raw.attr,
	&dev_attr_in5_label.attr,
	NULL
};

static const struct attribute_group apkpwr_group = {
	.attrs = apkpwr_attributes,
};


/*---------------------------------------------------------------------------*/
/* POWER_SUPPLY                                                              */
/*---------------------------------------------------------------------------*/

#ifdef APKPWR_POWER_SUPPLY

static int apkpwr_get_property(struct power_supply *psy,
			       enum power_supply_property psp,
			       union power_supply_propval *val)
{
	/*struct apkpwr_data *data = container_of(psy, struct apkpwr_data,
						bat_data[0].battery);*/
	struct apkpwr_data *data = power_supply_get_drvdata(psy);

	apkpwr_update_data(data);

	switch (psp) {
	case POWER_SUPPLY_PROP_STATUS:
		val->intval = data->bat_data[0].status;
		break;
	case POWER_SUPPLY_PROP_HEALTH:
		val->intval = data->bat_data[0].health;
		break;
	case POWER_SUPPLY_PROP_TECHNOLOGY:
		val->intval = POWER_SUPPLY_TECHNOLOGY_LION;
		break;
	case POWER_SUPPLY_PROP_PRESENT:
		val->intval = data->bat_data[0].present;
		break;
	case POWER_SUPPLY_PROP_ONLINE:
		val->intval = data->bat_data[0].online;
		break;
	case POWER_SUPPLY_PROP_CAPACITY_LEVEL:
		val->intval = data->bat_data[0].level;
		break;

	case POWER_SUPPLY_PROP_VOLTAGE_MAX:
		val->intval = CHARGE_MAX * 1000;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_MIN:
		val->intval = CHARGE_MIN * 1000;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		val->intval = data->bat_data[0].voltage;
		break;
	case POWER_SUPPLY_PROP_CAPACITY:
		val->intval = data->bat_data[0].capacity;
		break;
	case POWER_SUPPLY_PROP_TEMP:
		val->intval = data->bat_data[0].battemp;
		break;

	default:
		return -EINVAL;
	}
	return 0;
} /* apkpwr_get_property */


static enum power_supply_property apkpwr_battery_props[] = {
	POWER_SUPPLY_PROP_STATUS,
	POWER_SUPPLY_PROP_HEALTH,
	POWER_SUPPLY_PROP_TECHNOLOGY,
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_ONLINE,
	POWER_SUPPLY_PROP_CAPACITY_LEVEL,

	POWER_SUPPLY_PROP_VOLTAGE_MAX,
	POWER_SUPPLY_PROP_VOLTAGE_MIN,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_CAPACITY, /* in percents! */
	POWER_SUPPLY_PROP_TEMP,
};

#endif


/*---------------------------------------------------------------------------*/
/* I2C driver part                                                           */
/*---------------------------------------------------------------------------*/

/* Return 0 if detection is successful, -ENODEV otherwise */
static int apkpwr_detect(struct i2c_client *new_client,
			struct i2c_board_info *info)
{
	struct i2c_adapter *adapter = new_client->adapter;
	int address = new_client->addr;
	const char *name = DRIVER_NAME;
	s32 manid;

#ifdef DEBUG
	dev_info(&adapter->dev, "apkpwr_probe\n");
#endif /* DEBUG */

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE_DATA))
		return -ENODEV;

	manid = apkpwr_read_word(new_client, APKPWR_REG16_RO_ID);
	if (manid != MANUFACTURER_ID) {
		dev_err(&adapter->dev,
			"apkpwr detection failed: "
			"bad manufacturer id 0x%04x at 0x%02x\n",
			(u16)manid, address);
		return -ENODEV;
	}
	dev_info(&adapter->dev, "apkpwr detected at 0x%02x\n", address);

	/* Fill the i2c board info */
	strlcpy(info->type, name, I2C_NAME_SIZE);
	return 0;
} /* apkpwr_detect */


static int apkpwr_probe(struct i2c_client *client,
		       const struct i2c_device_id *id)
{
	struct apkpwr_data *data;
	struct power_supply_config psy_cfg = {};
	int err;

#ifdef DEBUG
	dev_info(&client->adapter->dev, "apkpwr_probe\n");
#endif /* DEBUG */

	data = kzalloc(sizeof(struct apkpwr_data), GFP_KERNEL);
	if (!data) {
		err = -ENOMEM;
		goto exit;
	}

	i2c_set_clientdata(client, data);
	data->client = client;
	mutex_init(&data->update_lock);

	data->rate = HZ;	/* 1 sec default */
	data->valid = 0;

	/* Register sysfs hooks */
	err = sysfs_create_group(&client->dev.kobj, &apkpwr_group);
	if (err)
		goto exit_free;

	/* hwmon */
	data->hwmon_dev = hwmon_device_register(&client->dev);
	if (IS_ERR(data->hwmon_dev)) {
		err = PTR_ERR(data->hwmon_dev);
		goto exit_remove_files;
	}
	dev_info(&client->dev, "hwmon device registered\n");


#ifdef APKPWR_POWER_SUPPLY
	/* power_supply */
	psy_cfg.drv_data = data;

	data->bat_data[0].battery_desc.name = kasprintf(GFP_KERNEL,
							"%s-%d",
							client->name,
							0/*num*/);
	if (!data->bat_data[0].battery_desc.name) {
		err = -ENOMEM;
		goto exit_remove_files;
	}
	data->bat_data[0].battery_desc.type =
		POWER_SUPPLY_TYPE_BATTERY;
	data->bat_data[0].battery_desc.get_property =
		apkpwr_get_property;
	data->bat_data[0].battery_desc.properties =
		apkpwr_battery_props;
	data->bat_data[0].battery_desc.num_properties =
		ARRAY_SIZE(apkpwr_battery_props);

	data->bat_data[0].battery = power_supply_register(&client->dev,
				    &data->bat_data[0].battery_desc,
				    &psy_cfg);
	if (IS_ERR(data->bat_data[0].battery)) {
		dev_err(&client->dev, "failed: power supply register\n");
		goto hwmon_unregister;
	}
	dev_info(&client->dev, "power_supply device registered\n");
#endif /* APKPWR_POWER_SUPPLY */

#ifdef CONFIG_DEBUG_FS
	apkpwr_dbgfs_init(client);
#endif /* CONFIG_DEBUG_FS */

#ifdef DEBUG
	dump_all_regs(client);
#endif /* DEBUG */

	return 0;

#ifdef APKPWR_POWER_SUPPLY
hwmon_unregister:
#endif /* APKPWR_POWER_SUPPLY */
	hwmon_device_unregister(data->hwmon_dev);
exit_remove_files:
	sysfs_remove_group(&client->dev.kobj, &apkpwr_group);
exit_free:
	kfree(data);
exit:
	return err;
} /* apkpwr_probe */


static int apkpwr_remove(struct i2c_client *client)
{
	struct apkpwr_data *data = i2c_get_clientdata(client);

#ifdef CONFIG_DEBUG_FS
	apkpwr_dbgfs_exit(client);
#endif /* CONFIG_DEBUG_FS */

#ifdef APKPWR_POWER_SUPPLY
	power_supply_unregister(data->bat_data[0].battery);
#endif /* APKPWR_POWER_SUPPLY */

	hwmon_device_unregister(data->hwmon_dev);
	sysfs_remove_group(&client->dev.kobj, &apkpwr_group);

	i2c_set_clientdata(client, NULL);
	mutex_destroy(&data->update_lock);
	kfree(data);

	return 0;
} /* apkpwr_remove */


/*---------------------------------------------------------------------------*/
/* Module part                                                               */
/*---------------------------------------------------------------------------*/

static const unsigned short normal_i2c[] = {0x5A, I2C_CLIENT_END};

#ifdef CONFIG_OF
static const struct of_device_id apkpwr_of_match[] = {
	{ .compatible = "mcst,apkpwr" },
	{ }
};

MODULE_DEVICE_TABLE(of, apkpwr_of_match);
#endif /* CONFIG_OF */

/* Driver data (common to all clients) */
static const struct i2c_device_id apkpwr_id[] = {
	{DRIVER_NAME, 0},
	{}
};
MODULE_DEVICE_TABLE(i2c, apkpwr_id);

static struct i2c_driver apkpwr_driver = {
	.class		= I2C_CLASS_HWMON,
	.driver = {
		.name	= DRIVER_NAME,
#ifdef CONFIG_OF
		.of_match_table = of_match_ptr(apkpwr_of_match),
#endif /* CONFIG_OF */
		.owner	= THIS_MODULE,
	},
	.probe		= apkpwr_probe,
	.remove		= apkpwr_remove,
	.id_table	= apkpwr_id,
	.detect		= apkpwr_detect,
	.address_list	= normal_i2c,
};

static int __init apkpwr_init(void)
{
	int err;
#ifdef DEBUG
	printk(KERN_INFO "apkpwr_init\n");
#endif /* DEBUG */

	err = i2c_add_driver(&apkpwr_driver);
#ifdef CONFIG_DEBUG_FS
	apkpwr_dbg_root = debugfs_create_dir(DRIVER_NAME, NULL);
#endif /* CONFIG_DEBUG_FS */
	return err;
}

static void __exit apkpwr_exit(void)
{
#ifdef CONFIG_DEBUG_FS
	debugfs_remove_recursive(apkpwr_dbg_root);
#endif /* CONFIG_DEBUG_FS */
	i2c_del_driver(&apkpwr_driver);
}


MODULE_AUTHOR("Andrey.V.Kalita@mcst.ru");
MODULE_DESCRIPTION("apkpwr driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRIVER_VERSION);

module_init(apkpwr_init);
module_exit(apkpwr_exit);
