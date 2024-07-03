 # SPDX-License-Identifier: GPL-2.0
 # Copyright (c) 2023 MCST
 
#!/bin/bash
echo "["
tr '\t' ' ' | tr -s ' ' ' ' | sed -e 's:":\\\\":g' -e '/^\s*$/d' | while read LINE; do
	DESC=$(echo $LINE | cut -d' ' -f 5-);
	SUPPORTED_MONITORS=$(echo $LINE | cut -d' ' -f 1 | sed -e 's/1000/0/g' -e 's/0100/1/g' -e 's/0010/2/g' -e 's/0001/3/g' -e 's/1100/0,1/g' -e 's/0011/2,3/g');
	RAW_SUPPORTED_MONITORS=$(echo $SUPPORTED_MONITORS | sed -e 's/0,1/4/g' -e 's/2,3/5/g')
	MON_EVENT=$(echo $LINE | cut -d' ' -f 2);
	MON=$(echo $MON_EVENT | cut -d':' -f 1);
	EVENT=$(echo $MON_EVENT | cut -d':' -f 2);
	EVENT=$(printf "%02x" "0x$EVENT");
	NAME=$(echo $LINE | cut -d' ' -f 3);
	printf '    {\n        "EventCode": "%s",\n        "EventName": "%s",\n        "BriefDescription": "%s",\n    },\n' "0x$RAW_SUPPORTED_MONITORS$EVENT" "$NAME" "$SUPPORTED_MONITORS:$EVENT $DESC";
done
echo "]"
>&2 echo WARNING add long descriptions under \`\"PublicDescription\":\'
