#!/bin/bash
#set -x # debugging
set -e # fail on any errors

OUTFILE=production_schema.sql
URL=postgres://tsdbadmin@ttfd71uhz4.m8ahrqo1nb.tsdb.cloud.timescale.com:33628/tsdb?sslmode=require


if [ -n "$PG_DUMP_USE_DOCKER" ] ; then
    # NOTE: do not specify the '-t' option as it merged stderr with stdout
    export PG_DUMP="docker run -i --rm  postgres pg_dump "
else
    PG_DUMP=pg_dump
fi

die() {
    echo $* >&2
    exit 1
}

if [ -d ./webserver ] ; then
    OUTDIR=./webserver
elif [ -d ../webserver ] ; then
    OUTDIR=../webserver
else 
    die "Unknown current working directory; can't find path to webserver";
fi

OUT=${OUTDIR}/${OUTFILE}

echo Enter the tsdbadmin password - this can not be the rw_user password
# Assumes you have postgresql-clients installed: https://www.postgresql.org/download/
$PG_DUMP --schema-only --schema public $URL > $OUT

# prepend autogen message
sed -i "1 s/^--/-- AUTO-GENERATED by .\/scripts\/sync_prod_schema_to_tree.sh on TZ=UTC `date -u`/" $OUT
# disable triggers
sed -i "s/CREATE TRIGGER /-- CREATE TRIGGER /" $OUT
# disable the thing that randomly breaks the search path!?
sed -i "s/^SELECT pg_catalog.set_config('search_path',/-- WTF!! SELECT pg_catalog.set_config('search_path',/" $OUT
