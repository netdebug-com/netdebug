-- AUTO-GENERATED by ./scripts/sync_prod_schema_to_tree.sh on TZ=UTC Sat Mar 30 00:40:34 UTC 2024
-- PostgreSQL database dump
--

-- Dumped from database version 15.6 (Ubuntu 15.6-1.pgdg22.04+1)
-- Dumped by pg_dump version 16.2 (Debian 16.2-1.pgdg120+2)

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


SET default_tablespace = '';

SET default_table_access_method = heap;

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
    device_uuid uuid
);


ALTER TABLE public.desktop_counters OWNER TO tsdbadmin;

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
    device_uuid uuid
);


ALTER TABLE public.desktop_logs OWNER TO tsdbadmin;

--
-- Name: desktop_connections; Type: TABLE; Schema: public; Owner: tsdbadmin
--

CREATE TABLE public.desktop_connections (
    local_ip text,
    remote_ip text,
    local_port integer,
    remote_port integer,
    ip_protocol smallint,
    local_hostname text,
    remote_hostname text,
    probe_report_summary text,
    user_annotation text,
    user_agent text,
    associated_apps text,
    close_has_started boolean,
    four_way_close_done boolean,
    start_tracking_time timestamp with time zone,
    last_packet_time timestamp with time zone,
    tx_loss bigint,
    rx_loss bigint,
    tx_stats text,
    rx_stats text,
    "time" timestamp with time zone NOT NULL,
    client_uuid uuid,
    source_type text,
    device_uuid uuid
);


ALTER TABLE public.desktop_connections OWNER TO tsdbadmin;

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
-- Name: desktop_connections_time_idx; Type: INDEX; Schema: public; Owner: tsdbadmin
--

CREATE INDEX desktop_connections_time_idx ON public.desktop_connections USING btree ("time" DESC);


--
-- Name: desktop_counters_time_idx; Type: INDEX; Schema: public; Owner: tsdbadmin
--

CREATE INDEX desktop_counters_time_idx ON public.desktop_counters USING btree ("time" DESC);


--
-- Name: desktop_logs_time_idx; Type: INDEX; Schema: public; Owner: tsdbadmin
--

CREATE INDEX desktop_logs_time_idx ON public.desktop_logs USING btree ("time" DESC);


--
-- Name: desktop_connections ts_insert_blocker; Type: TRIGGER; Schema: public; Owner: tsdbadmin
--

-- CREATE TRIGGER ts_insert_blocker BEFORE INSERT ON public.desktop_connections FOR EACH ROW EXECUTE FUNCTION _timescaledb_functions.insert_blocker();


--
-- Name: desktop_counters ts_insert_blocker; Type: TRIGGER; Schema: public; Owner: tsdbadmin
--

-- CREATE TRIGGER ts_insert_blocker BEFORE INSERT ON public.desktop_counters FOR EACH ROW EXECUTE FUNCTION _timescaledb_functions.insert_blocker();


--
-- Name: desktop_logs ts_insert_blocker; Type: TRIGGER; Schema: public; Owner: tsdbadmin
--

-- CREATE TRIGGER ts_insert_blocker BEFORE INSERT ON public.desktop_logs FOR EACH ROW EXECUTE FUNCTION _timescaledb_functions.insert_blocker();


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: tsdbadmin
--

GRANT USAGE ON SCHEMA public TO tsdbexplorer;


--
-- Name: TABLE desktop_counters; Type: ACL; Schema: public; Owner: tsdbadmin
--

GRANT SELECT ON TABLE public.desktop_counters TO readaccess;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.desktop_counters TO rw_updater;


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

