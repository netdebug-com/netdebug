

# All of the local_ips logged in the last hour

    select count(*), local_ip from desktop_connections where time > (NOW() - INTERVAL '1 hour') GROUP BY local_ip;