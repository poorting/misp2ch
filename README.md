# misp2clickhouse

Tool to extract IoCs from MISP with a specific filter and insert them into a clickhouse database

This allows fairly easy discovery of appearance of IoCs in netflow data.
## iocs table
The table specified in the misp2ch.conf file ('nfsen.iocs' by default) has the following schema:

```
┌─name────────┬─type─────┐
│ ts          │ DateTime │
│ misp        │ String   │
│ uuid        │ String   │
│ event_uuid  │ String   │
│ event_id    │ UInt32   │
│ ip          │ String   │
│ port        │ UInt16   │
│ info        │ String   │
└─────────────┴──────────┘
```
## What the script does

1. Creates the nfsen.iocs table if it does not exist already
2. Retrieve IoCs (attributes) of type `ip-dst|port` from MISP that have `to_ids` set. 
   - Limit this further e.g. by adding a tag to `json_req` in the conf file.
4. Delete all IoCs from the table which are not present in the  list from MISP (remove older IoCs).
   - Can be disabled by setting `remove_old = False` in the conf file, e.g.`json_req = {"tags":"my_tag","last":"3d"}`
5. Add those IoCs to the table that are not there already (add new ones)

See `misp2.conf.default` for an example of a configuration file and which entries need to be in there.

## Running the script
First create a virtual environment suited for the script:
```
python3 -m venv venv
source venv/bin/activate
pip install wheel
pip install -r requirements.txt
```
The script needs to be started with a configuration file as a parameter, e.g.
```
./misp2ch.py -c misp2ch.conf
```
The scrip will provide info on what it is doing. If you want more details add `--debug` as a parameter.


By running this script at regular intervals, the iocs table will be kept up to date with the MISP. This can be done automatically via a cron job such as this:

```
20 * * * * /<path_to_misp2ch>/venv/bin/python /<path_to_misp2ch>/misp2ch.py -c /<path_to_misp2ch>/misp2ch.conf -l /<path_to_misp2ch>/misp2ch.log
```
Which will run the script every 20 minutes past the hour.
By adding the `-l <path/to/logfile>`, the output of the script will be added to the logfile specified.

Of course the configuration and log file need not be in the same location as the script itself.

## Discovering IoCs in netflow data

### Direct query
To check whether there are flows that 'hit' an IoC use an SQL query such as:

```
SELECT ts, sa, da, dp, ipkt, ibyt, event_id, info FROM nfsen.flows INNER JOIN nfsen.iocs ON (flows.da = iocs.ip) AND (flows.dp = iocs.port) WHERE ts > now() - toIntervalDay(7);
```
This query shows all those flows over the past 7 days. Of course you can also use a fixed starting date, useful if you check every so often and want to search from the point where the last search ended.

```
SELECT ts, sa, da, dp, ipkt, ibyt, event_id, info FROM nfsen.flows INNER JOIN nfsen.iocs ON (flows.da = iocs.ip) AND (flows.dp = iocs.port) WHERE ts > '2024-04-01 00:00:00';
```
### Materialized Views

It's also possible to let ClickHouse check for IoCs automatically by using [materialized views](https://clickhouse.com/docs/en/guides/developer/cascading-materialized-views).

First create a table for holding the results:
```
use nfsen

CREATE TABLE nfsen.ioc_hits
(
    `misp` String,
    `source_ip` String,
    `destination_ip` String,
    `dp` UInt16,
    `pkt` UInt64,
    `byt` UInt64,
    `reverse` UInt8,
    `event_uuid` String,
    `id` UInt32,
    `attr_uuid` String,
    `ts` DateTime,
    `te` DateTime,
    `info` String
)
ENGINE = MergeTree
PARTITION BY tuple()
PRIMARY KEY (ts, source_ip)
ORDER BY (ts, source_ip)
TTL te + toIntervalDay(90);
```

Then create the materialized views, one for the normal flows and one for the reverse (since nfdump2clickhouse inserts raw flows they are unidirectional).

```
CREATE MATERIALIZED VIEW nfsen.ioc_hits_mv TO nfsen.ioc_hits
AS SELECT
    misp,
    sa AS source_ip,
    da AS destination_ip,
    dp,
    ipkt AS pkt,
    ibyt AS byt,
    0 AS reverse,
    event_uuid,
    event_id AS id,
    uuid AS attr_uuid,
    ts,
    te,
    info
FROM nfsen.flows
INNER JOIN nfsen.iocs ON (flows.da = iocs.ip) AND (flows.dp = iocs.port);

CREATE MATERIALIZED VIEW nfsen.ioc_hits_rev_mv TO nfsen.ioc_hits
AS SELECT
    misp,
    da AS source_ip,
    sa AS destination_ip,
    sp AS dp,
    ipkt AS pkt,
    ibyt AS byt,
    1 AS reverse,
    event_uuid,
    event_id AS id,
    uuid AS attr_uuid,
    ts,
    te,
    info
FROM nfsen.flows
INNER JOIN nfsen.iocs ON (flows.sa = iocs.ip) AND (flows.sp = iocs.port);
```

The ioc_hits table will now automatically be updated whenever a new flow meets the criteria of the SQL query.
To check for IoC hits you only need to check the ioc_hits table every now and then and see if there are any new entries.

**_Please note that only new flows will be evaluated. Adding a new IoC will (therefore) not lead to re-evaluation of existing flow data!_ 
This means you have to check manually if you want to evaluate new IoCs against existing flow data!**
