# Notes for various timescaledb/postgres admin tasks

1. Install 'psql'
    ```
    sudo apt install postgresql-client-common
    ```
2. Get an admin or read-only password from the website or Rob; store in ```$HOME/.secrets.toml```
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

1. The file ./webserver/production_schema.sql contains a snapshot of the production DB's schema.  The prod DB itself is the
    source of truth.
2. With timescaledb, each table needs to be marked as a 'hypertable' which tells the backend to treat it with timeseries optimizations:
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
4. User auth info: 
  * These need to be run whenever you add a table:
    ```
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO readaccess;
    GRANT SELECT,INSERT,DELETE,UPDATE ON ALL TABLES IN SCHEMA public TO rw_updater;
    ```
  * More info: https://docs.timescale.com/use-timescale/latest/security/client-credentials/

5. TODO: setup 'continuous aggregates' to continuously downsample our data
    https://docs.timescale.com/use-timescale/latest/data-retention/data-retention-with-continuous-aggregates/
    NOT DONE YET!

6. TODO: Consider using Timescale's "tiered storage" because we don't need high performance on this data;
    details are here: https://docs.timescale.com/use-timescale/latest/data-tiering/

  * Create a read-only user using SQL ala https://docs.timescale.com/use-timescale/latest/security/read-only-role/
  * I created 'read_user' and granted access to the desktop_* tables.