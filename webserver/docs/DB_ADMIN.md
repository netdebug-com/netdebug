# Notes for various timescaledb/postgres admin tasks

1. Install 'psql'
    ```
    sudo apt install postgresql-client-common
    ```
2. Get an admin password from the website or Rob; store in ```$HOME/.timescaledb_auth```
    (no, there does not yet appear to be an OAUTH system.. I think)
3. The URL for our private db is 
    ```
    postgres://tsdbadmin@ttfd71uhz4.m8ahrqo1nb.tsdb.cloud.timescale.com:33628/tsdb?sslmode=require
    ```
4. Launch the psql command with url, enter password to get to the admin prompt
    ```
    psql postgres://tsdbadmin@ttfd71uhz4.m8ahrqo1nb.tsdb.cloud.timescale.com:33628/tsdb?sslmode=require
    ```
    'psql' has a bunch of useful commands you can find with '\?', e.g., list tables `\dt` or list schema `\d desktop_counters`


# One time setup/database initialization

1. Create the 'desktop_counters' and 'desktop_logs' table with the schema from `RemoteDBClient::create_table_schema()`, 
    e.g., :
    ```
    CREATE TABLE desktop_counters ( counter TEXT, value BIGINT, os TEXT, version TEXT, source TEXT, time TIMESTAMPTZ);
    CREATE TABLE desktop_logs ( msg TEXT, level TEXT, os TEXT, version TEXT, source TEXT, time TIMESTAMPTZ);

    CREATE TABLE desktop_connections ( connection_key TEXT,  local_hostname TEXT,  remote_hostname TEXT,  
            probe_report_summary TEXT,  user_annotation TEXT, user_agent TEXT, associated_apps TEXT, 
            close_has_started BOOLEAN, four_way_close_done BOOLEAN, start_tracking_time TIMESTAMPTZ, 
            last_packet_time TIMESTAMPTZ, tx_loss BIGINT, rx_loss BIGINT, tx_stats TEXT, rx_stats TEXT, time TIMESTAMPTZ);
    ```
2. Mark them as a 'hypertable' which tells the backend to treat it with timeseries optimizations:
    ```
    SELECT create_hypertable('desktop_counters', by_range('time'));
    SELECT create_hypertable('desktop_logs', by_range('time'));
    SELECT create_hypertable('desktop_connections', by_range('time'));
    ```
3. Set a data retention policy for how long we hold on to data.  This will auto-delete data older than 30 days.
    Read more about it here:
    https://docs.timescale.com/use-timescale/latest/data-retention/
    ```
    SELECT add_retention_policy('desktop_counters', INTERVAL '30 days');
    SELECT add_retention_policy('desktop_logs', INTERVAL '30 days');
    SELECT add_retention_policy('desktop_connections', INTERVAL '30 days');
    ```
4. TODO: setup 'continuous aggregates' to continuously downsample our data
    https://docs.timescale.com/use-timescale/latest/data-retention/data-retention-with-continuous-aggregates/
    NOT DONE YET!

5. TODO: Consider using Timescale's "tiered storage" because we don't need high performance on this data;
    details are here: https://docs.timescale.com/use-timescale/latest/data-tiering/
