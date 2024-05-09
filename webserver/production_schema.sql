-- AUTO-GENERATED by ./scripts/sync_prod_schema_to_tree.sh on TZ=UTC Thu May  9 15:55:42 UTC 2024
-- PostgreSQL database dump
--

-- Dumped from database version 15.6 (Ubuntu 15.6-1.pgdg22.04+1)
-- Dumped by pg_dump version 15.6 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
-- WTF!! SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: tsdbadmin
--

CREATE SCHEMA public;


ALTER SCHEMA public OWNER TO tsdbadmin;

--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: tsdbadmin
--

COMMENT ON SCHEMA public IS 'standard public schema';


--
-- Name: create_playground(regclass, boolean); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.create_playground(src_hypertable regclass, compressed boolean DEFAULT false) RETURNS text
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
DECLARE
    _table_name NAME;
    _schema_name NAME;
    _src_relation NAME;
    _playground_table_fqn NAME;
    _chunk_name NAME;
    _chunk_check BOOL;
    _playground_schema_check BOOL;
    _next_id INTEGER;
    _dimension TEXT;
    _interval TEXT;
    _segmentby_cols TEXT;
    _orderby_cols TEXT;
BEGIN
    SELECT EXISTS(SELECT 1 FROM information_schema.schemata
    WHERE schema_name = 'tsdb_playground') INTO _playground_schema_check;

    IF NOT _playground_schema_check THEN
        RAISE EXCEPTION '"tsdb_playground" schema must be created before running this';
    END IF;

    -- get schema and table name
    SELECT n.nspname, c.relname INTO _schema_name, _table_name
    FROM pg_class c
    INNER JOIN pg_namespace n ON (n.oid = c.relnamespace)
    INNER JOIN timescaledb_information.hypertables i ON (i.hypertable_name = c.relname )
    WHERE c.oid = src_hypertable;

    IF _table_name IS NULL THEN
        RAISE EXCEPTION '% is not a hypertable', src_hypertable;
    END IF;

    SELECT EXISTS(SELECT 1 FROM timescaledb_information.chunks WHERE hypertable_name = _table_name AND hypertable_schema = _schema_name) INTO _chunk_check;

    IF NOT _chunk_check THEN
        RAISE EXCEPTION '% has no chunks for playground testing', src_hypertable;
    END IF;

    EXECUTE pg_catalog.format($$ CREATE SEQUENCE IF NOT EXISTS tsdb_playground.%I $$, _table_name||'_seq');
    SELECT pg_catalog.nextval('tsdb_playground.' || pg_catalog.quote_ident(_table_name || '_seq')) INTO _next_id;

    SELECT pg_catalog.format('%I.%I', _schema_name, _table_name) INTO _src_relation;

    SELECT pg_catalog.format('tsdb_playground.%I', _table_name || '_' || _next_id::text) INTO _playground_table_fqn;

    EXECUTE pg_catalog.format(
        $$ CREATE TABLE %s (like %s including comments including constraints including defaults including indexes) $$
        , _playground_table_fqn, _src_relation
        );

    -- get dimension column from src ht for partitioning playground ht
    SELECT column_name, time_interval INTO _dimension, _interval FROM timescaledb_information.dimensions WHERE hypertable_name = _table_name AND hypertable_schema = _schema_name LIMIT 1;

    PERFORM public.create_hypertable(_playground_table_fqn::REGCLASS, _dimension::NAME, chunk_time_interval := _interval::interval);

    -- Ideally, it should pick up the latest complete chunk (second last chunk) from this hypertable.
    -- If num_chunks > 1 then it will get true, converted into 1, taking the second row, otherwise it'll get false converted to 0 and get no offset.
    SELECT
        format('%I.%I',chunk_schema,chunk_name)
    INTO STRICT
        _chunk_name
    FROM
        timescaledb_information.chunks
    WHERE
        hypertable_schema = _schema_name AND
        hypertable_name = _table_name
    ORDER BY
        chunk_creation_time DESC OFFSET (
            SELECT
                (num_chunks > 1)::integer
            FROM timescaledb_information.hypertables
            WHERE
                hypertable_name = _table_name)
    LIMIT 1;
	EXECUTE pg_catalog.format($$ INSERT INTO %s SELECT * FROM %s $$, _playground_table_fqn, _chunk_name);

    IF compressed THEN
        --retrieve compression settings from source hypertable
        SELECT segmentby INTO _segmentby_cols
        FROM timescaledb_information.hypertable_compression_settings 
        WHERE hypertable = _src_relation::REGCLASS;

		SELECT orderby INTO _orderby_cols
		FROM timescaledb_information.hypertable_compression_settings 
        WHERE hypertable = _src_relation::REGCLASS;

        IF (_segmentby_cols IS NOT NULL) AND (_orderby_cols IS NOT NULL) THEN
            EXECUTE pg_catalog.format(
                $$ ALTER TABLE %s SET(timescaledb.compress, timescaledb.compress_segmentby = %I, timescaledb.compress_orderby = %I) $$
                , _playground_table_fqn, _segmentby_cols, _orderby_cols
                );
        ELSE
            EXECUTE pg_catalog.format(
                $$ ALTER TABLE %s SET(timescaledb.compress) $$
                , _playground_table_fqn
                );
        END IF;
        -- get playground chunk and compress
    PERFORM public.compress_chunk(public.show_chunks(_playground_table_fqn::REGCLASS));
    END IF;

	RETURN _playground_table_fqn;
END
$_$;


ALTER FUNCTION public.create_playground(src_hypertable regclass, compressed boolean) OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: desktop_dns_entries; Type: TABLE; Schema: public; Owner: tsdbadmin
--

CREATE TABLE public.desktop_dns_entries (
    "time" timestamp with time zone DEFAULT now() NOT NULL,
    ip text NOT NULL,
    hostname text NOT NULL,
    created timestamp with time zone NOT NULL,
    from_ptr_record boolean NOT NULL,
    rtt_usec bigint,
    ttl_sec bigint,
    device_uuid uuid NOT NULL
);


ALTER TABLE public.desktop_dns_entries OWNER TO tsdbadmin;

--
-- Name: desktop_aggregated_ping_data; Type: TABLE; Schema: public; Owner: tsdbadmin
--

CREATE TABLE public.desktop_aggregated_ping_data (
    "time" timestamp with time zone DEFAULT now() NOT NULL,
    network_interface_state_uuid uuid NOT NULL,
    gateway_ip text NOT NULL,
    num_probes_sent bigint NOT NULL,
    num_responses_recv bigint NOT NULL,
    rtt_mean_ns bigint NOT NULL,
    rtt_variance_ns bigint,
    rtt_min_ns bigint NOT NULL,
    rtt_p50_ns bigint NOT NULL,
    rtt_p75_ns bigint NOT NULL,
    rtt_p90_ns bigint NOT NULL,
    rtt_p99_ns bigint NOT NULL,
    rtt_max_ns bigint NOT NULL
);


ALTER TABLE public.desktop_aggregated_ping_data OWNER TO tsdbadmin;

--
-- Name: desktop_counters; Type: TABLE; Schema: public; Owner: tsdbadmin
--

CREATE TABLE public.desktop_counters (
    counter text,
    value bigint,
    os text,
    version text,
    source text,
    "time" timestamp with time zone NOT NULL,
    device_uuid uuid NOT NULL
);


ALTER TABLE public.desktop_counters OWNER TO tsdbadmin;

--
-- Name: desktop_network_interface_state; Type: TABLE; Schema: public; Owner: tsdbadmin
--

CREATE TABLE public.desktop_network_interface_state (
    "time" timestamp with time zone DEFAULT now() NOT NULL,
    state_uuid uuid NOT NULL,
    gateways text[] NOT NULL,
    interface_name text,
    interface_ips text[] NOT NULL,
    comment text NOT NULL,
    has_link boolean NOT NULL,
    is_wireless boolean NOT NULL,
    start_time timestamp with time zone NOT NULL,
    end_time timestamp with time zone,
    device_uuid uuid NOT NULL
);


ALTER TABLE public.desktop_network_interface_state OWNER TO tsdbadmin;

--
-- Name: aggregated_connections_total; Type: TABLE; Schema: public; Owner: tsdbadmin
--

CREATE TABLE public.aggregated_connections_total (
    bucket_start_time timestamp with time zone NOT NULL,
    bucket_size_minutes bigint NOT NULL,
    device_uuid uuid NOT NULL,
    organization bigint DEFAULT 1 NOT NULL,
    num_flows bigint NOT NULL,
    num_flows_with_rx_loss bigint,
    num_flows_with_tx_loss bigint,
    num_tcp_flows bigint NOT NULL,
    num_udp_flows bigint NOT NULL,
    rx_packets bigint NOT NULL,
    tx_packets bigint NOT NULL,
    rx_bytes bigint NOT NULL,
    tx_bytes bigint NOT NULL,
    rx_lost_bytes bigint,
    tx_lost_bytes bigint,
    tcp_rx_bytes bigint NOT NULL,
    tcp_tx_bytes bigint NOT NULL,
    udp_rx_bytes bigint NOT NULL,
    udp_tx_bytes bigint NOT NULL
);


ALTER TABLE public.aggregated_connections_total OWNER TO tsdbadmin;

--
-- Name: aggregated_connections_by_dest; Type: TABLE; Schema: public; Owner: tsdbadmin
--

CREATE TABLE public.aggregated_connections_by_dest (
    bucket_start_time timestamp with time zone NOT NULL,
    bucket_size_minutes bigint NOT NULL,
    device_uuid uuid NOT NULL,
    organization bigint DEFAULT 1 NOT NULL,
    dns_dest_domain text NOT NULL,
    num_flows bigint NOT NULL,
    num_flows_with_rx_loss bigint,
    num_flows_with_tx_loss bigint,
    num_tcp_flows bigint NOT NULL,
    num_udp_flows bigint NOT NULL,
    rx_packets bigint NOT NULL,
    tx_packets bigint NOT NULL,
    rx_bytes bigint NOT NULL,
    tx_bytes bigint NOT NULL,
    rx_lost_bytes bigint,
    tx_lost_bytes bigint,
    tcp_rx_bytes bigint NOT NULL,
    tcp_tx_bytes bigint NOT NULL,
    udp_rx_bytes bigint NOT NULL,
    udp_tx_bytes bigint NOT NULL
);


ALTER TABLE public.aggregated_connections_by_dest OWNER TO tsdbadmin;

--
-- Name: aggregated_connections_by_application; Type: TABLE; Schema: public; Owner: tsdbadmin
--

CREATE TABLE public.aggregated_connections_by_application (
    bucket_start_time timestamp with time zone NOT NULL,
    bucket_size_minutes bigint NOT NULL,
    device_uuid uuid NOT NULL,
    organization bigint DEFAULT 1 NOT NULL,
    application text NOT NULL,
    num_flows bigint NOT NULL,
    num_flows_with_rx_loss bigint,
    num_flows_with_tx_loss bigint,
    num_tcp_flows bigint NOT NULL,
    num_udp_flows bigint NOT NULL,
    rx_packets bigint NOT NULL,
    tx_packets bigint NOT NULL,
    rx_bytes bigint NOT NULL,
    tx_bytes bigint NOT NULL,
    rx_lost_bytes bigint,
    tx_lost_bytes bigint,
    tcp_rx_bytes bigint NOT NULL,
    tcp_tx_bytes bigint NOT NULL,
    udp_rx_bytes bigint NOT NULL,
    udp_tx_bytes bigint NOT NULL
);


ALTER TABLE public.aggregated_connections_by_application OWNER TO tsdbadmin;

--
-- Name: desktop_logs; Type: TABLE; Schema: public; Owner: tsdbadmin
--

CREATE TABLE public.desktop_logs (
    msg text,
    level text,
    os text,
    version text,
    source text,
    "time" timestamp with time zone NOT NULL,
    device_uuid uuid NOT NULL
);


ALTER TABLE public.desktop_logs OWNER TO tsdbadmin;

--
-- Name: desktop_connections; Type: TABLE; Schema: public; Owner: tsdbadmin
--

CREATE TABLE public.desktop_connections (
    local_ip text NOT NULL,
    remote_ip text NOT NULL,
    local_port integer NOT NULL,
    remote_port integer NOT NULL,
    ip_protocol smallint NOT NULL,
    local_hostname text,
    remote_hostname text,
    probe_report_summary text NOT NULL,
    user_annotation text,
    user_agent text,
    associated_apps text NOT NULL,
    close_has_started boolean NOT NULL,
    four_way_close_done boolean NOT NULL,
    start_tracking_time timestamp with time zone NOT NULL,
    last_packet_time timestamp with time zone NOT NULL,
    tx_loss bigint,
    rx_loss bigint,
    tx_stats text NOT NULL,
    rx_stats text NOT NULL,
    "time" timestamp with time zone NOT NULL,
    client_uuid uuid,
    source_type text NOT NULL,
    device_uuid uuid NOT NULL,
    pingtrees text DEFAULT '[]'::text NOT NULL,
    was_evicted boolean DEFAULT true NOT NULL,
    organization bigint DEFAULT 1 NOT NULL,
    rx_stats_since_prev_export text,
    tx_stats_since_prev_export text,
    prev_export_time timestamp with time zone,
    export_count bigint DEFAULT 0 NOT NULL
);


ALTER TABLE public.desktop_connections OWNER TO tsdbadmin;

--
-- Name: aggregated_connections_lock; Type: TABLE; Schema: public; Owner: tsdbadmin
--

CREATE TABLE public.aggregated_connections_lock (
    next_bucket_start_time timestamp with time zone NOT NULL
);


ALTER TABLE public.aggregated_connections_lock OWNER TO tsdbadmin;

--
-- Name: devices; Type: TABLE; Schema: public; Owner: tsdbadmin
--

CREATE TABLE public.devices (
    uuid uuid NOT NULL,
    organization bigint NOT NULL,
    salt text,
    crypt text,
    name text,
    description text,
    created timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.devices OWNER TO tsdbadmin;

--
-- Name: organizations; Type: TABLE; Schema: public; Owner: tsdbadmin
--

CREATE TABLE public.organizations (
    id bigint NOT NULL,
    name text,
    admin_contact text,
    description text,
    created timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.organizations OWNER TO tsdbadmin;

--
-- Name: users; Type: TABLE; Schema: public; Owner: tsdbadmin
--

CREATE TABLE public.users (
    clerk_id text NOT NULL,
    primary_email text,
    name text,
    organization bigint NOT NULL,
    created time with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.users OWNER TO tsdbadmin;

--
-- Name: aggregated_connections_by_application aggregated_connections_by_application_pkey; Type: CONSTRAINT; Schema: public; Owner: tsdbadmin
--

ALTER TABLE ONLY public.aggregated_connections_by_application
    ADD CONSTRAINT aggregated_connections_by_application_pkey PRIMARY KEY (bucket_start_time, device_uuid, application);


--
-- Name: aggregated_connections_by_dest aggregated_connections_by_dest_pkey; Type: CONSTRAINT; Schema: public; Owner: tsdbadmin
--

ALTER TABLE ONLY public.aggregated_connections_by_dest
    ADD CONSTRAINT aggregated_connections_by_dest_pkey PRIMARY KEY (bucket_start_time, device_uuid, dns_dest_domain);


--
-- Name: aggregated_connections_total aggregated_connections_total_pkey; Type: CONSTRAINT; Schema: public; Owner: tsdbadmin
--

ALTER TABLE ONLY public.aggregated_connections_total
    ADD CONSTRAINT aggregated_connections_total_pkey PRIMARY KEY (bucket_start_time, device_uuid);


--
-- Name: devices devices_pkey; Type: CONSTRAINT; Schema: public; Owner: tsdbadmin
--

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_pkey PRIMARY KEY (uuid);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: tsdbadmin
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: tsdbadmin
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (clerk_id);


--
-- Name: aggregated_connections_by_application_bucket_start_time_idx; Type: INDEX; Schema: public; Owner: tsdbadmin
--

CREATE INDEX aggregated_connections_by_application_bucket_start_time_idx ON public.aggregated_connections_by_application USING btree (bucket_start_time DESC);


--
-- Name: aggregated_connections_by_dest_bucket_start_time_idx; Type: INDEX; Schema: public; Owner: tsdbadmin
--

CREATE INDEX aggregated_connections_by_dest_bucket_start_time_idx ON public.aggregated_connections_by_dest USING btree (bucket_start_time DESC);


--
-- Name: aggregated_connections_total_bucket_start_time_idx; Type: INDEX; Schema: public; Owner: tsdbadmin
--

CREATE INDEX aggregated_connections_total_bucket_start_time_idx ON public.aggregated_connections_total USING btree (bucket_start_time DESC);


--
-- Name: desktop_aggregated_ping_data_time_idx; Type: INDEX; Schema: public; Owner: tsdbadmin
--

CREATE INDEX desktop_aggregated_ping_data_time_idx ON public.desktop_aggregated_ping_data USING btree ("time" DESC);


--
-- Name: desktop_aggregated_ping_data_time_idx2; Type: INDEX; Schema: public; Owner: tsdbadmin
--

CREATE INDEX desktop_aggregated_ping_data_time_idx2 ON public.desktop_aggregated_ping_data USING btree (network_interface_state_uuid);


--
-- Name: desktop_connections_time_idx; Type: INDEX; Schema: public; Owner: tsdbadmin
--

CREATE INDEX desktop_connections_time_idx ON public.desktop_connections USING btree ("time" DESC);


--
-- Name: desktop_counters_time_idx; Type: INDEX; Schema: public; Owner: tsdbadmin
--

CREATE INDEX desktop_counters_time_idx ON public.desktop_counters USING btree ("time" DESC);


--
-- Name: desktop_dns_entries_time_idx; Type: INDEX; Schema: public; Owner: tsdbadmin
--

CREATE INDEX desktop_dns_entries_time_idx ON public.desktop_dns_entries USING btree ("time" DESC);


--
-- Name: desktop_logs_time_idx; Type: INDEX; Schema: public; Owner: tsdbadmin
--

CREATE INDEX desktop_logs_time_idx ON public.desktop_logs USING btree ("time" DESC);


--
-- Name: desktop_network_interface_state_time_idx; Type: INDEX; Schema: public; Owner: tsdbadmin
--

CREATE INDEX desktop_network_interface_state_time_idx ON public.desktop_network_interface_state USING btree ("time" DESC);


--
-- Name: desktop_network_interface_state_time_idx2; Type: INDEX; Schema: public; Owner: tsdbadmin
--

CREATE INDEX desktop_network_interface_state_time_idx2 ON public.desktop_network_interface_state USING btree (state_uuid);


--
-- Name: idx_desktop_connections_by_device_uuid; Type: INDEX; Schema: public; Owner: tsdbadmin
--

CREATE INDEX idx_desktop_connections_by_device_uuid ON public.desktop_connections USING hash (device_uuid);


--
-- Name: aggregated_connections_by_application ts_insert_blocker; Type: TRIGGER; Schema: public; Owner: tsdbadmin
--

-- CREATE TRIGGER ts_insert_blocker BEFORE INSERT ON public.aggregated_connections_by_application FOR EACH ROW EXECUTE FUNCTION _timescaledb_functions.insert_blocker();


--
-- Name: aggregated_connections_by_dest ts_insert_blocker; Type: TRIGGER; Schema: public; Owner: tsdbadmin
--

-- CREATE TRIGGER ts_insert_blocker BEFORE INSERT ON public.aggregated_connections_by_dest FOR EACH ROW EXECUTE FUNCTION _timescaledb_functions.insert_blocker();


--
-- Name: aggregated_connections_total ts_insert_blocker; Type: TRIGGER; Schema: public; Owner: tsdbadmin
--

-- CREATE TRIGGER ts_insert_blocker BEFORE INSERT ON public.aggregated_connections_total FOR EACH ROW EXECUTE FUNCTION _timescaledb_functions.insert_blocker();


--
-- Name: desktop_aggregated_ping_data ts_insert_blocker; Type: TRIGGER; Schema: public; Owner: tsdbadmin
--

-- CREATE TRIGGER ts_insert_blocker BEFORE INSERT ON public.desktop_aggregated_ping_data FOR EACH ROW EXECUTE FUNCTION _timescaledb_functions.insert_blocker();


--
-- Name: desktop_connections ts_insert_blocker; Type: TRIGGER; Schema: public; Owner: tsdbadmin
--

-- CREATE TRIGGER ts_insert_blocker BEFORE INSERT ON public.desktop_connections FOR EACH ROW EXECUTE FUNCTION _timescaledb_functions.insert_blocker();


--
-- Name: desktop_counters ts_insert_blocker; Type: TRIGGER; Schema: public; Owner: tsdbadmin
--

-- CREATE TRIGGER ts_insert_blocker BEFORE INSERT ON public.desktop_counters FOR EACH ROW EXECUTE FUNCTION _timescaledb_functions.insert_blocker();


--
-- Name: desktop_dns_entries ts_insert_blocker; Type: TRIGGER; Schema: public; Owner: tsdbadmin
--

-- CREATE TRIGGER ts_insert_blocker BEFORE INSERT ON public.desktop_dns_entries FOR EACH ROW EXECUTE FUNCTION _timescaledb_functions.insert_blocker();


--
-- Name: desktop_logs ts_insert_blocker; Type: TRIGGER; Schema: public; Owner: tsdbadmin
--

-- CREATE TRIGGER ts_insert_blocker BEFORE INSERT ON public.desktop_logs FOR EACH ROW EXECUTE FUNCTION _timescaledb_functions.insert_blocker();


--
-- Name: desktop_network_interface_state ts_insert_blocker; Type: TRIGGER; Schema: public; Owner: tsdbadmin
--

-- CREATE TRIGGER ts_insert_blocker BEFORE INSERT ON public.desktop_network_interface_state FOR EACH ROW EXECUTE FUNCTION _timescaledb_functions.insert_blocker();


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: tsdbadmin
--

GRANT USAGE ON SCHEMA public TO tsdbexplorer;


--
-- Name: TABLE desktop_dns_entries; Type: ACL; Schema: public; Owner: tsdbadmin
--

GRANT SELECT ON TABLE public.desktop_dns_entries TO readaccess;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.desktop_dns_entries TO rw_updater;


--
-- Name: TABLE desktop_aggregated_ping_data; Type: ACL; Schema: public; Owner: tsdbadmin
--

GRANT SELECT ON TABLE public.desktop_aggregated_ping_data TO readaccess;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.desktop_aggregated_ping_data TO rw_updater;


--
-- Name: TABLE desktop_counters; Type: ACL; Schema: public; Owner: tsdbadmin
--

GRANT SELECT ON TABLE public.desktop_counters TO readaccess;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.desktop_counters TO rw_updater;


--
-- Name: TABLE desktop_network_interface_state; Type: ACL; Schema: public; Owner: tsdbadmin
--

GRANT SELECT ON TABLE public.desktop_network_interface_state TO readaccess;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.desktop_network_interface_state TO rw_updater;


--
-- Name: TABLE aggregated_connections_total; Type: ACL; Schema: public; Owner: tsdbadmin
--

GRANT SELECT ON TABLE public.aggregated_connections_total TO readaccess;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.aggregated_connections_total TO rw_updater;


--
-- Name: TABLE aggregated_connections_by_dest; Type: ACL; Schema: public; Owner: tsdbadmin
--

GRANT SELECT ON TABLE public.aggregated_connections_by_dest TO readaccess;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.aggregated_connections_by_dest TO rw_updater;


--
-- Name: TABLE aggregated_connections_by_application; Type: ACL; Schema: public; Owner: tsdbadmin
--

GRANT SELECT ON TABLE public.aggregated_connections_by_application TO readaccess;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.aggregated_connections_by_application TO rw_updater;


--
-- Name: TABLE desktop_logs; Type: ACL; Schema: public; Owner: tsdbadmin
--

GRANT SELECT ON TABLE public.desktop_logs TO readaccess;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.desktop_logs TO rw_updater;


--
-- Name: TABLE desktop_connections; Type: ACL; Schema: public; Owner: tsdbadmin
--

GRANT SELECT ON TABLE public.desktop_connections TO readaccess;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.desktop_connections TO rw_updater;


--
-- Name: TABLE aggregated_connections_lock; Type: ACL; Schema: public; Owner: tsdbadmin
--

GRANT SELECT ON TABLE public.aggregated_connections_lock TO readaccess;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.aggregated_connections_lock TO rw_updater;


--
-- Name: TABLE devices; Type: ACL; Schema: public; Owner: tsdbadmin
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.devices TO rw_updater;
GRANT SELECT ON TABLE public.devices TO readaccess;


--
-- Name: TABLE organizations; Type: ACL; Schema: public; Owner: tsdbadmin
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.organizations TO rw_updater;
GRANT SELECT ON TABLE public.organizations TO readaccess;


--
-- Name: TABLE users; Type: ACL; Schema: public; Owner: tsdbadmin
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.users TO rw_updater;
GRANT SELECT ON TABLE public.users TO readaccess;


--
-- PostgreSQL database dump complete
--

