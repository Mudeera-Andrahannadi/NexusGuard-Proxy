package com.demo.netguard.monitor;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.Executors;

/** Read-only, LOCALHOST-ONLY dashboard; not an authenticated network admin console. */
public final class DashboardServer implements AutoCloseable {
    private final HttpServer server;
    private final EventLog log;
    public DashboardServer(int port,EventLog log) throws IOException {
        this.log=log;
        server=HttpServer.create(new InetSocketAddress("127.0.0.1",port),0);
        server.setExecutor(Executors.newCachedThreadPool(r->{Thread t=new Thread(r,"dashboard");t.setDaemon(true);return t;}));
        server.createContext("/api/events", e -> {
            Map<String,String> q=query(e.getRequestURI().getRawQuery());
            int limit=100;
            try{limit=Integer.parseInt(q.getOrDefault("limit","100"));}catch(NumberFormatException ignored){}
            reply(e,200,"application/json",log.recentJson(limit,q.getOrDefault("client",""),q.getOrDefault("domain","")));
        });
        server.createContext("/api/summary",e->reply(e,200,"application/json",log.summaryJson()));
        server.createContext("/api/status",e->reply(e,200,"application/json",storageStatus()));
        server.createContext("/health",e->reply(e,200,"text/plain","ok"));
        server.createContext("/",e->reply(e,200,"text/html",PAGE));
    }
    /** Can the event log still be written? Checked on request, so EventLog stays untouched. */
    private String storageStatus() {
        Path file=log.file();
        boolean writable=!Files.isDirectory(file) && (Files.exists(file)?Files.isWritable(file):Files.isWritable(file.getParent()));
        return writable?"{\"storage\":\"ok\"}":"{\"storage\":\"error\"}";
    }
    private static Map<String,String> query(String raw) {
        Map<String,String> m=new HashMap<>();
        if(raw==null || raw.length()>1024)return m;
        for(String part:raw.split("&",6)) {
            String[] kv=part.split("=",2);
            if(kv.length==2)try{m.put(URLDecoder.decode(kv[0],StandardCharsets.UTF_8),
                URLDecoder.decode(kv[1],StandardCharsets.UTF_8));}catch(IllegalArgumentException ignored){}
        }
        return m;
    }
    private static void reply(HttpExchange e,int status,String type,String response) throws IOException {
        e.getResponseHeaders().set("Content-Type",type+"; charset=utf-8");
        e.getResponseHeaders().set("Cache-Control","no-store");
        e.getResponseHeaders().set("Content-Security-Policy","default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'");
        byte[] data=response.getBytes(StandardCharsets.UTF_8);e.sendResponseHeaders(status,data.length);
        try(var out=e.getResponseBody()){out.write(data);}
    }
    private static final String PAGE="""
        <!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
        <title>NexusGuard Proxy</title>
        <style>body{font:15px system-ui;background:#0f172a;color:#f8fafc;max-width:1050px;margin:30px auto;padding:0 16px}
        h1{font-size:25px}section{background:#1e293b;padding:17px;border-radius:10px;margin:16px 0}
        label{display:inline-block;margin:0 12px 8px 0}input,select{background:#0f172a;color:#fff;border:1px solid #64748b;border-radius:5px;padding:7px;font:inherit}
        select{color-scheme:dark}input:focus-visible,select:focus-visible{outline:2px solid #38bdf8;outline-offset:2px}
        table{border-collapse:collapse;width:100%;font-size:13px}td,th{text-align:left;border-bottom:1px solid #475569;padding:8px}
        .small{color:#cbd5e1;font-size:13px}td.empty{color:#cbd5e1;padding:24px 8px}
        .notice{background:#3b1111;color:#fecaca;border:1px solid #b91c1c;border-radius:8px;padding:10px 14px;margin:16px 0}</style>
        <h1>NexusGuard Proxy</h1><p>Only proxy metadata is recorded. No IDS or threat classification exists yet.</p>
        <div id="notice" class="notice" role="status" hidden></div>
        <section><h2>Connection summary</h2><div id="totals">Loading...</div></section>
        <section><h2>Recent proxied connections</h2>
        <label>Client IP <input id="client" placeholder="192.168.1.10"></label>
        <label>Domain <input id="domain" placeholder="example.com"></label>
        <label>Time range <select id="range"><option value="0">All retained</option><option value="5">Last 5 minutes</option>
        <option value="60">Last hour</option><option value="1440">Last 24 hours</option></select></label>
        <p class="small">HTTPS CONNECT destination only; no URL paths, credentials or encrypted content.</p>
        <p class="small" id="shown"></p>
        <table><thead><tr><th>Time</th><th>Client</th><th>Protocol</th><th>Destination</th><th>Outcome</th></tr></thead><tbody id="entries"></tbody></table>
        </section><script>
        function td(row,value){const cell=document.createElement('td');cell.textContent=String(value);row.appendChild(cell)}
        // shortcut: the time range is applied in the browser over the 500 retained events; add a since= param to /api/events if retention grows
        const get=url=>fetch(url).then(r=>{if(!r.ok)throw new Error(r.status);return r.json()});
        function notice(text){const n=document.getElementById('notice');n.hidden=!text;n.textContent=text||''}
        function emptyRow(body,text){const tr=document.createElement('tr'),cell=document.createElement('td');cell.colSpan=5;cell.className='empty';cell.textContent=text;tr.appendChild(cell);body.appendChild(tr)}
        let latest=0;
        async function refresh(){const id=++latest;try{
          const params=new URLSearchParams({client:document.getElementById('client').value.trim(),domain:document.getElementById('domain').value.trim(),limit:'500'});
          const [summary,events,status]=await Promise.all([get('/api/summary'),get('/api/events?'+params),get('/api/status')]);
          if(id!==latest)return;
          notice(status.storage==='ok'?'':"Can't write to the event log, so new connections may not be recorded. Check disk space and permissions on the data folder.");
          const minutes=Number(document.getElementById('range').value);
          const rows=minutes?events.filter(e=>Date.parse(e.at)>=Date.now()-minutes*60000):events;
          document.getElementById('shown').textContent=`Showing ${rows.length} of ${events.length} matching events`;
          document.getElementById('totals').textContent=`Recent: ${summary.recentTotal} | Connected: ${summary.connected} | Failed: ${summary.failed} | Denied by safe-demo rules: ${summary.denied}`;
          const body=document.getElementById('entries');body.replaceChildren();
          for(const e of rows){const tr=document.createElement('tr');[e.at,e.sourceIp,e.protocol,e.destination+':'+e.port,e.outcome].forEach(x=>td(tr,x));body.appendChild(tr)}
          if(!rows.length)emptyRow(body,events.length?'No events in this time range. Try a wider range.':(params.get('client')||params.get('domain'))?'Nothing matches these filters.':'Waiting for the first connection. Send a request through the proxy and it will show up here.');
        }catch(e){if(id===latest)notice("Can't reach the dashboard server. Retrying...")}}
        for(const id of ['client','domain','range'])document.getElementById(id).addEventListener('input',refresh);
        refresh();setInterval(refresh,2500);</script></html>
        """;
    public void start(){server.start();}
    public int port(){return server.getAddress().getPort();}
    @Override public void close(){server.stop(0);}
}
