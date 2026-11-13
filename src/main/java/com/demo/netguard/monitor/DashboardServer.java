package com.demo.netguard.monitor;

import com.demo.netguard.security.ClientGuard;
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
    private final ClientGuard guard; // null when rate limiting is off
    public DashboardServer(int port,EventLog log) throws IOException {
        this(port,log,null);
    }
    public DashboardServer(int port,EventLog log,ClientGuard guard) throws IOException {
        this.log=log;
        this.guard=guard;
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
        server.createContext("/api/blocked",e->reply(e,200,"application/json",blockedJson()));
        server.createContext("/health",e->reply(e,200,"text/plain","ok"));
        server.createContext("/",e->reply(e,200,"text/html",PAGE));
    }
    /** Can the event log still be written? Checked on request, so EventLog stays untouched. */
    private String storageStatus() {
        Path file=log.file();
        boolean writable=!Files.isDirectory(file) && (Files.exists(file)?Files.isWritable(file):Files.isWritable(file.getParent()));
        return writable?"{\"storage\":\"ok\"}":"{\"storage\":\"error\"}";
    }
    /** Clients the rate limiter is blocking right now, with whole seconds left (rounded up). */
    private String blockedJson() {
        if(guard==null)return "[]";
        StringJoiner json=new StringJoiner(",","[","]");
        guard.blocked().forEach((ip,millis)->json.add("{\"ip\":\""+ip+"\",\"remainingSeconds\":"+(millis+999)/1000+"}"));
        return json.toString();
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
        h1{font-size:25px}h2{font-size:17px;margin:0 0 10px}section{background:#1e293b;padding:17px;border-radius:10px;margin:16px 0}
        label{display:inline-block;margin:0 12px 8px 0}input,select{background:#0f172a;color:#fff;border:1px solid #64748b;border-radius:5px;padding:7px;font:inherit}
        select{color-scheme:dark}input:focus-visible,select:focus-visible{outline:2px solid #38bdf8;outline-offset:2px}
        table{border-collapse:collapse;width:100%;font-size:13px}td,th{text-align:left;border-bottom:1px solid #475569;padding:8px}
        .scroll{overflow-x:auto}.small{color:#cbd5e1;font-size:13px}td.empty{color:#cbd5e1;padding:24px 8px}
        .notice{background:#3b1111;color:#fecaca;border:1px solid #b91c1c;border-radius:8px;padding:10px 14px;margin:16px 0}
        .tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:8px 0 16px}
        .tile{background:#1e293b;border-radius:10px;padding:12px 14px}.tile span{display:block}
        .tile b{display:block;font-size:24px;font-weight:500;font-variant-numeric:tabular-nums}.tile b.hot{color:#fecaca}
        .two{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}.two section{margin:0}
        .badge{display:inline-block;padding:1px 8px;border-radius:6px;font-size:12px;border:1px solid #475569;white-space:nowrap}
        .badge.threat{background:#3b1111;color:#fecaca;border-color:#b91c1c}
        .badge.policy,.badge.failed{background:#33270a;color:#fde68a;border-color:#a16207}
        tr.threat td{background:#2a1620}</style>
        <h1>NexusGuard Proxy</h1><p>Only connection metadata is recorded. Clients that send too many requests, and requests that match known attack patterns, are blocked.</p>
        <div id="alert" class="notice" role="status" hidden></div>
        <div id="notice" class="notice" role="status" hidden></div>
        <label>Time range <select id="range"><option value="0">All retained</option><option value="5">Last 5 minutes</option>
        <option value="60">Last hour</option><option value="1440">Last 24 hours</option></select></label>
        <div class="tiles">
        <div class="tile"><span class="small">Threats blocked</span><b id="tThreats">0</b><span class="small">in this time range</span></div>
        <div class="tile"><span class="small">Clients blocked now</span><b id="tBlocked">0</b><span class="small">temporary blocks</span></div>
        <div class="tile"><span class="small">Most common threat</span><b id="tTop">None</b><span class="small" id="tTopSub"></span></div>
        <div class="tile"><span class="small">Connections</span><b id="tConn">0</b><span class="small" id="tConnSub"></span></div>
        </div>
        <div class="two">
        <section><h2>Clients</h2><div class="scroll"><table><thead><tr><th>Client</th><th>Requests</th><th>Threats</th><th>Status</th></tr></thead><tbody id="clients"></tbody></table></div></section>
        <section><h2>Recent alerts</h2><div class="scroll"><table><thead><tr><th>Time</th><th>Threat</th><th>Client</th></tr></thead><tbody id="alerts"></tbody></table></div></section>
        </div>
        <section><h2>Recent proxied connections</h2>
        <label>Client IP <input id="client" placeholder="192.168.1.10"></label>
        <label>Domain <input id="domain" placeholder="example.com"></label>
        <label>Show <select id="show"><option value="all">All results</option><option value="threat">Threats only</option><option value="policy">Policy denials only</option></select></label>
        <p class="small">HTTPS CONNECT destination only; no URL paths, credentials or encrypted content.</p>
        <p class="small" id="shown"></p>
        <div class="scroll"><table><thead><tr><th>Time</th><th>Client</th><th>Protocol</th><th>Destination</th><th>Result</th></tr></thead><tbody id="entries"></tbody></table></div>
        </section><script>
        const $=id=>document.getElementById(id);
        function td(row,value){const cell=document.createElement('td');cell.textContent=String(value);row.appendChild(cell)}
        // shortcut: the time range, tiles, clients and alerts are all worked out in the browser from the 500 retained events; add a since= param to /api/events if retention grows
        const get=url=>fetch(url).then(r=>{if(!r.ok)throw new Error(r.status);return r.json()});
        function show(id,text){const n=$(id);n.hidden=!text;n.textContent=text||''}
        function emptyRow(body,text,span){const tr=document.createElement('tr'),cell=document.createElement('td');cell.colSpan=span||5;cell.className='empty';cell.textContent=text;tr.appendChild(cell);body.appendChild(tr)}
        function badge(text,kind){const s=document.createElement('span');s.className='badge '+kind;s.textContent=text;return s}
        const THREATS={RATE_LIMIT_EXCEEDED:'Rate limit',DIRECTORY_TRAVERSAL:'Directory traversal',SQL_INJECTION:'SQL injection',XSS:'Cross-site scripting',SCANNER_USER_AGENT:'Scanner agent'};
        const POLICY={DESTINATION_POLICY:'Destination not allowed',REQUEST_BODY_UNSUPPORTED:'Request body not supported'};
        const isThreat=e=>e.outcome==='DENIED'&&(e.reason==='RATE_LIMIT_EXCEEDED'||e.reason.startsWith('MALICIOUS_PATTERN_DETECTED:'));
        const threatName=e=>THREATS[e.reason.split(':').pop()]||e.reason;
        function result(e){
          if(isThreat(e))return{kind:'threat',text:'Blocked · '+threatName(e)};
          if(e.outcome==='DENIED')return{kind:'policy',text:'Denied · '+(POLICY[e.reason]||e.reason)};
          if(e.outcome==='FAILED')return{kind:'failed',text:'Failed'};
          return{kind:'',text:'Connected'}}
        const left=until=>{const s=Math.max(0,Math.ceil((until-Date.now())/1000));return 'Blocked '+Math.floor(s/60)+':'+String(s%60).padStart(2,'0')};
        function row(e){const r=result(e),tr=document.createElement('tr');if(r.kind==='threat')tr.className='threat';
          td(tr,new Date(e.at).toLocaleString());td(tr,e.sourceIp);td(tr,e.protocol);td(tr,e.destination==='-'?'-':e.destination+':'+e.port);
          const cell=document.createElement('td');if(r.kind)cell.appendChild(badge(r.text,r.kind));else cell.textContent=r.text;tr.appendChild(cell);return tr}
        function renderTiles(list,blocked){
          const threats=list.filter(isThreat),names=new Map();
          for(const e of threats)names.set(threatName(e),(names.get(threatName(e))||0)+1);
          const ranked=[...names].sort((a,b)=>b[1]-a[1]),top=ranked[0],tied=ranked.length>1&&ranked[1][1]===top[1];
          const policy=list.filter(e=>e.outcome==='DENIED'&&!isThreat(e)).length,failed=list.filter(e=>e.outcome==='FAILED').length;
          $('tThreats').textContent=threats.length;$('tThreats').className=threats.length?'hot':'';
          $('tBlocked').textContent=blocked.length;
          $('tTop').textContent=!top?'None':tied?'Mixed':top[0];$('tTopSub').textContent=!top?'':tied?names.size+' kinds, tied':top[1]+' of '+threats.length;
          $('tConn').textContent=list.length;$('tConnSub').textContent=policy+' denied by policy, '+failed+' failed'}
        function renderClients(list,blocked){
          const byIp=new Map(),until=new Map(blocked.map(b=>[b.ip,Date.now()+b.remainingSeconds*1000]));
          for(const e of list){const c=byIp.get(e.sourceIp)||{ip:e.sourceIp,requests:0,threats:0};c.requests++;if(isThreat(e))c.threats++;byIp.set(e.sourceIp,c)}
          for(const ip of until.keys())if(!byIp.has(ip))byIp.set(ip,{ip:ip,requests:0,threats:0});
          const body=$('clients');body.replaceChildren();
          const rows=[...byIp.values()].sort((a,b)=>until.has(b.ip)-until.has(a.ip)||b.threats-a.threats||b.requests-a.requests);
          for(const c of rows){const tr=document.createElement('tr'),cell=document.createElement('td');td(tr,c.ip);td(tr,c.requests);td(tr,c.threats);
            if(until.has(c.ip)){const b=badge(left(until.get(c.ip)),'threat');b.dataset.until=until.get(c.ip);cell.appendChild(b)}else cell.textContent='Normal';
            tr.appendChild(cell);body.appendChild(tr)}
          if(!rows.length)emptyRow(body,'No clients yet.',4)}
        function renderAlerts(list){
          const body=$('alerts'),hits=list.filter(isThreat).slice(-8).reverse();body.replaceChildren();
          for(const e of hits){const tr=document.createElement('tr'),cell=document.createElement('td');td(tr,new Date(e.at).toLocaleTimeString());
            cell.appendChild(badge(threatName(e),'threat'));tr.appendChild(cell);td(tr,e.sourceIp);body.appendChild(tr)}
          if(!hits.length)emptyRow(body,'No threats in this time range.',3)}
        let latest=0;
        async function refresh(){const id=++latest;try{
          const params=new URLSearchParams({client:$('client').value.trim(),domain:$('domain').value.trim(),limit:'500'});
          const filtered=params.get('client')||params.get('domain');
          const [events,status,blocked,everyone]=await Promise.all([get('/api/events?'+params),get('/api/status'),get('/api/blocked'),filtered?get('/api/events?limit=500'):null]);
          if(id!==latest)return;
          show('notice',status.storage==='ok'?'':"Can't write to the event log, so new connections may not be recorded. Check disk space and permissions on the data folder.");
          const all=everyone||events,minutes=Number($('range').value);
          const within=list=>minutes?list.filter(e=>Date.parse(e.at)>=Date.now()-minutes*60000):list;
          const recent=all.filter(e=>isThreat(e)&&Date.parse(e.at)>=Date.now()-60000).length;
          show('alert',[recent?recent+(recent===1?' request':' requests')+' blocked in the last minute.':'',blocked.length?blocked.length+(blocked.length===1?' client is':' clients are')+' blocked right now.':''].filter(Boolean).join(' '));
          document.title=recent?'('+recent+') NexusGuard Proxy':'NexusGuard Proxy';
          const overview=within(all);renderTiles(overview,blocked);renderClients(overview,blocked);renderAlerts(overview);
          const view=$('show').value,inRange=within(events);
          const rows=inRange.filter({all:()=>true,threat:isThreat,policy:e=>e.outcome==='DENIED'&&!isThreat(e)}[view]);
          $('shown').textContent=`Showing ${rows.length} of ${events.length} matching events`;
          const body=$('entries');body.replaceChildren();
          for(const e of rows.slice().reverse())body.appendChild(row(e));
          if(!rows.length)emptyRow(body,!events.length?(filtered?'Nothing matches these filters.':'Waiting for the first connection. Send a request through the proxy and it will show up here.'):!inRange.length?'No events in this time range. Try a wider range.':view==='threat'?'No blocked threats in this view.':'No policy denials in this view.');
        }catch(e){if(id===latest)show('notice',"Can't reach the dashboard server. Retrying...")}}
        for(const id of ['client','domain','range','show'])$(id).addEventListener('input',refresh);
        setInterval(()=>{for(const el of document.querySelectorAll('[data-until]'))el.textContent=left(Number(el.dataset.until))},1000);
        refresh();setInterval(refresh,2500);</script></html>
        """;
    public void start(){server.start();}
    public int port(){return server.getAddress().getPort();}
    @Override public void close(){server.stop(0);}
}
