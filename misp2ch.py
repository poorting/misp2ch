#! /usr/bin/env python3
import json
import os
import sys
import time
import pprint
import logging
from logging import handlers
import argparse
import configparser
import textwrap

import requests
import urllib3
import clickhouse_driver

program_name = os.path.basename(__file__)
VERSION = 0.1

###############################################################################
class ArgumentParser(argparse.ArgumentParser):

    def error(self, message):
        print('\n\033[1;33mError: {}\x1b[0m\n'.format(message))
        self.print_help(sys.stderr)
        # self.exit(2, '%s: error: %s\n' % (self.prog, message))
        self.exit(2)

###############################################################################
class CustomConsoleFormatter(logging.Formatter):
    """
        Log facility format
    """

    def format(self, record):
        # info = '\033[0;32m'
        info = ''
        warning = '\033[0;33m'
        error = '\033[1;33m'
        debug = '\033[1;34m'
        reset = "\x1b[0m"

        formatter = "%(asctime)s %(levelname)s - %(message)s"
        if record.levelno == logging.INFO:
            log_fmt = info + formatter + reset
            self._style._fmt = log_fmt
        elif record.levelno == logging.WARNING:
            log_fmt = warning + formatter + reset
            self._style._fmt = log_fmt
        elif record.levelno == logging.ERROR:
            log_fmt = error + formatter + reset
            self._style._fmt = log_fmt
        elif record.levelno == logging.DEBUG:
            # formatter = '%(asctime)s %(levelname)s [%(filename)s.py:%(lineno)s/%(funcName)s] %(message)s'
            formatter = '%(levelname)s [%(filename)s:%(lineno)s/%(funcName)s] %(message)s'
            log_fmt = debug + formatter + reset
            self._style._fmt = log_fmt
        else:
            self._style._fmt = formatter

        return super().format(record)
###############################################################################
# Subroutines
def get_logger(logfile=None, debug=False):
    logger = logging.getLogger(program_name)

    # Create handlers
    console_handler = logging.StreamHandler()
    console_formatter = CustomConsoleFormatter()
    console_handler.setFormatter(console_formatter)

    if logfile:
        file_handler = logging.handlers.RotatingFileHandler(filename=logfile, backupCount=2, maxBytes=10**7)
        file_formatter = logging.Formatter('%(asctime)s  %(levelname)-5s %(filename)-10s %(lineno)d %(funcName)-20s %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    else:
        logger.addHandler(console_handler)

    logger.setLevel(logging.INFO)

    if debug:
        logger.setLevel(logging.DEBUG)

    return logger


# ------------------------------------------------------------------------------
def parser_add_arguments():
    """
        Parse command line parameters
    """
    parser = ArgumentParser(
        prog=program_name,
        description=textwrap.dedent('''\
                        Gets IoCsd from MISP, inserts into CH.
                        '''),
        formatter_class=argparse.RawTextHelpFormatter, )

    parser.add_argument("-c",
                        metavar='config file',
                        help=textwrap.dedent('''\
                        load config from this file. 
                        '''),
                        action="store",
                        default=''
                        )

    parser.add_argument("-l",
                        metavar='log file',
                        help=textwrap.dedent('''\
                        Log to the specified file instead
                        of logging to console.
                        '''),
                        action="store",
                        )

    parser.add_argument("--debug",
                        help="show debug output",
                        action="store_true")

    parser.add_argument("-V", "--version",
                        help="print version and exit",
                        action="version",
                        version='%(prog)s (version {})'.format(VERSION))

    return parser


# ------------------------------------------------------------------------------
def create_tables(logger, client, ch_db_iocs, ch_db_hits, ch_db_flows):

    try:
        tbl_create = f"""
            CREATE TABLE IF NOT EXISTS {ch_db_iocs}
            (
                ts TIMESTAMP,
                misp String,
                uuid String,
                event_uuid String,
                event_id UInt32,
                ip String,
                port UInt16 DEFAULT 0,
                info String DEFAULT '',
                insert_ts TIMESTAMP DEFAULT now(),
            )
            ENGINE = MergeTree
            PARTITION BY tuple()
            PRIMARY KEY (ip, port)
            ORDER BY (ip, port) 
        """
        res = client.execute(tbl_create)
    except Exception as e:
        logger.error(e)
        exit(3)

    try:
        tbl_create = f"""
            CREATE TABLE IF NOT EXISTS {ch_db_hits}
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
                `info` String,
                `insert_ts` TIMESTAMP DEFAULT now(),
            )
            ENGINE = MergeTree
            PARTITION BY tuple()
            PRIMARY KEY (ts, source_ip)
            ORDER BY (ts, source_ip)
            TTL te + toIntervalDay(90)
        """
        res = client.execute(tbl_create)
    except Exception as e:
        logger.error(e)
        exit(3)

    try:
        tbl_create = f"""
            CREATE MATERIALIZED VIEW IF NOT EXISTS {ch_db_hits}_mv TO {ch_db_hits}
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
            AS SELECT
                {ch_db_iocs}.misp,
                {ch_db_flows}.sa AS source_ip,
                {ch_db_flows}.da AS destination_ip,
                {ch_db_flows}.dp as dp,
                {ch_db_flows}.ipkt AS pkt,
                {ch_db_flows}.ibyt AS byt,
                0 AS reverse,
                {ch_db_iocs}.event_uuid,
                {ch_db_iocs}.event_id AS id,
                {ch_db_iocs}.uuid AS attr_uuid,
                {ch_db_flows}.ts,
                {ch_db_flows}.te,
                {ch_db_iocs}.info
            FROM {ch_db_flows}
            INNER JOIN {ch_db_iocs} ON ({ch_db_flows}.da = {ch_db_iocs}.ip) AND ({ch_db_flows}.dp = {ch_db_iocs}.port)
        """
        res = client.execute(tbl_create)
    except Exception as e:
        logger.error(e)
        exit(3)

    try:
        tbl_create = f"""
            CREATE MATERIALIZED VIEW IF NOT EXISTS {ch_db_hits}_rev_mv TO {ch_db_hits}
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
            AS SELECT
                {ch_db_iocs}.misp,
                {ch_db_flows}.da AS source_ip,
                {ch_db_flows}.sa AS destination_ip,
                {ch_db_flows}.sp AS dp,
                {ch_db_flows}.ipkt AS pkt,
                {ch_db_flows}.ibyt AS byt,
                1 AS reverse,
                {ch_db_iocs}.event_uuid,
                {ch_db_iocs}.event_id AS id,
                {ch_db_iocs}.uuid AS attr_uuid,
                {ch_db_flows}.ts,
                {ch_db_flows}.te,
                {ch_db_iocs}.info
            FROM {ch_db_flows}
            INNER JOIN {ch_db_iocs} ON ({ch_db_flows}.sa = {ch_db_iocs}.ip) AND ({ch_db_flows}.sp = {ch_db_iocs}.port)
        """
        res = client.execute(tbl_create)
    except Exception as e:
        logger.error(e)
        exit(3)


def do_backscan(logger, client, ch_db_flows, ch_db_iocs, ch_db_hits, backscan, misp):

    pp = pprint.PrettyPrinter(indent=4)

    try:
        sql = f"""
            INSERT INTO {ch_db_hits} 
            (misp, source_ip, destination_ip, dp, pkt, byt, reverse, event_uuid, id, attr_uuid, ts, te, info)
            SELECT
                {ch_db_iocs}.misp,
                {ch_db_flows}.sa AS source_ip,
                {ch_db_flows}.da AS destination_ip,
                {ch_db_flows}.dp,
                {ch_db_flows}.ipkt AS pkt,
                {ch_db_flows}.ibyt AS byt,
                0 AS reverse,
                {ch_db_iocs}.event_uuid as event_uuid,
                {ch_db_iocs}.event_id AS id,
                {ch_db_iocs}.uuid AS attr_uuid,
                {ch_db_flows}.ts,
                {ch_db_flows}.te,
                {ch_db_iocs}.info
            FROM {ch_db_flows}, {ch_db_iocs}
            WHERE {ch_db_flows}.ts>now()-toIntervalDay({backscan}) AND {ch_db_iocs}.misp='{misp}' 
            AND {ch_db_iocs}.insert_ts>now()-toIntervalMinute(5) AND {ch_db_flows}.da = {ch_db_iocs}.ip 
            AND {ch_db_flows}.dp = {ch_db_iocs}.port AND {ch_db_flows}.ts<{ch_db_iocs}.insert_ts;
        """
        logger.info(f"Scanning back for {backscan} days")
        start = time.time()
        res = client.execute(sql)
        duration = time.time()-start
        logger.info(f"Backscan took {duration:.2f} seconds")

    except Exception as e:
        logger.error(e)


###############################################################################
def main():

    pp = pprint.PrettyPrinter(indent=4)

    parser = parser_add_arguments()
    args = parser.parse_args()

    if not args.c:
        parser.error("No config file provided")
        exit(1)

    logger = get_logger(args.l, args.debug)
    logger.debug("Logging level set to debug")

    if not os.path.isfile(args.c):
        logger.error(f"Specified config file ({args.c}) is not a file")
        exit(2)

    # See if we have a config file
    config = configparser.ConfigParser()
    config.read(args.c)
    try:
        misp_fqdn = config['misp']['misp_fqdn']
        token = config['misp']['token']
        verify_tls = bool(config['misp'].getboolean('verify_tls', True))
        json_req = config['misp'].get('json_req', '{}')
        ch_db_iocs = config['clickhouse'].get('ch_db_iocs', 'nfsen.iocs')
        ch_db_hits = config['clickhouse'].get('ch_db_hits', 'nfsen.ioc_hits')
        ch_db_flows = config['clickhouse'].get('ch_db_flows', 'nfsen.flows')
        ch_remove_old = bool(config['clickhouse'].getboolean('remove_old', True))
        backscan = int(config['clickhouse'].get('backscan', 0))
    except KeyError:
        logger.error("Missing configuration items")
        exit(1)

    json_dict = json.loads(json_req)
    json_dict['returnFormat'] = 'json'
    json_dict['type'] = 'ip-dst|port'
    json_dict['to_ids'] = '1'

    logger.debug(json_dict)

    # Create database and table if they do not already exist
    client = clickhouse_driver.Client(host='localhost',  settings={'use_numpy': False})

    create_tables(logger, client, ch_db_iocs, ch_db_hits, ch_db_flows)

    # Retrieve IoCs from the misp server if possible
    logger.debug(f"Retrieving IoCs from https://{misp_fqdn}")

    if not verify_tls:
        urllib3.disable_warnings()

    try:
        response = requests.post(f'https://{misp_fqdn}/attributes/restSearch',
                                 json=json_dict or dict(),
                                 headers={'Authorization': token,
                                          'Accept': 'application/json'},
                                 timeout=10, verify=verify_tls)
    except Exception as e:
        logger.error(e)
        exit(4)

    try:
        response.raise_for_status()
        # return response.json()
    except requests.HTTPError:
        logger.critical(f'Retrieving MISP Event attributes responded with status code:{response.status_code}')
        exit(5)
    attrib_json = response.json()

    # f = open('sunet-iocs.json')
    # attrib_json = json.load(f)
    # f.close()

    attribs = attrib_json['response']['Attribute']
    logger.info(f"{len(attribs)} IoCs returned from {misp_fqdn}")

    # Create the list as a dict
    attr_dict = {}
    if len(attribs) > 0:
        for attr in attribs:
            ts = int(attr['timestamp'])
            uuid=attr['uuid']
            event_uuid=attr['Event']['uuid']
            event_id=int(attr['Event']['id'])
            info=attr['Event']['info']
            info = json.dumps(info, ensure_ascii=True)[1:-1]
            # Ensure insert doesn't choke on ' in string
            info = info.replace("'", "\\'")
            ip_port = attr['value']
            ip = ip_port.split('|')[0]
            port = int(ip_port.split('|')[1])
            attr_dict[uuid] = {
                'ts': ts,
                'misp': misp_fqdn,
                'uuid': uuid,
                'event_uuid': event_uuid,
                'event_id': event_id,
                'ip': ip,
                'port': port,
                'info': info,
            }

    # print(json.dumps(attr_dict))

    # Retrieve all existing IoCs from the database (for this misp)
    sqlq = f"select uuid from {ch_db_iocs} where misp='{misp_fqdn}'"
    results = client.execute(sqlq)
    exist_uuids = [result[0] for result in results]
    logger.info(f"{len(exist_uuids)} existing IoCs in {ch_db_iocs}")

    attr_uuids = list(attr_dict.keys())

    if ch_remove_old:
        # See which uuids from the db are not in the misp list
        del_uuids = [uuid for uuid in exist_uuids if uuid not in attr_uuids]
        logger.info(f"{len(del_uuids)} IoCs to delete")
        # limit delete to 5000 uuids at a time so as to not exceed max query size
        for i in range(0, len(del_uuids), 5000):
            end = i+5000
            if end>len(del_uuids):
                end = len(del_uuids)
            logger.debug(f"deleting IoCs [{i}:{end}] for {misp_fqdn} from {ch_db_iocs}")
            uuidstr = "','".join(del_uuids[i:end])
            sqlq = f"alter table {ch_db_iocs} delete where misp='{misp_fqdn}' and uuid in ('{uuidstr}')"
            client.execute(sqlq)
    else:
        logger.info("Configured not to remove outdated IoCs")

    # Now compare all IoCs from MISP to this list
    # Only add the ones not already in the database
    iocs = []
    for uuid in attr_uuids:
        if uuid not in exist_uuids:
            iocs.append(attr_dict[uuid])

    logger.info(f'{len(iocs)} IoCs to insert')
    if len(iocs) > 0:
        # Rework the IoCs into an insert statement
        iocs_str = [f"({ioc['ts']}, '{ioc['misp']}', '{ioc['uuid']}', '{ioc['event_uuid']}', '{ioc['event_id']}', '{ioc['ip']}', {ioc['port']}, '{ioc['info']}')" for ioc in iocs]
        sqlq = f'INSERT INTO {ch_db_iocs} (ts, misp, uuid, event_uuid, event_id, ip, port, info) VALUES '+','.join(iocs_str)
        # print(sqlq)
        client.execute(sqlq)

        # See if we need to do a backscan
        if backscan>0:
            do_backscan(logger, client, ch_db_flows, ch_db_iocs, ch_db_hits, backscan, misp_fqdn)


###############################################################################
if __name__ == '__main__':
    # Run the main process
    main()
