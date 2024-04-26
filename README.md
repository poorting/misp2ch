# misp2clickhouse

Tool to extract IoCs from MISP with a specific filter and insert them into a clickhouse database.

This allows fairly easy discovery of appearance of IoCs in netflow data. Use [nfdump2clickhouse](https://github.com/poorting/nfdump2clickhouse) to insert flow data into clickhouse. 
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
