package com.trace.app;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.HashSet;
import java.util.Set;

public final class IntelligenceUtils {
    private IntelligenceUtils() {}
    public static JSONObject graph(JSONObject evidence) {
        JSONObject graph=new JSONObject(); JSONArray nodes=new JSONArray(); JSONArray edges=new JSONArray();
        try {
            String target=evidence.optString("target",evidence.optString("normalizedUrl","unknown")); node(nodes,"target",target,"TARGET");
            JSONObject dns=evidence.optJSONObject("dns"); if(dns!=null){node(nodes,"dns", "DNS","DNS"); edge(edges,"target","dns","resolves");}
            JSONObject tls=evidence.optJSONObject("tls"); if(tls!=null){node(nodes,"tls","TLS certificate","TLS"); edge(edges,"target","tls","secured-by");}
            JSONObject tech=evidence.optJSONObject("technology"); if(tech!=null){node(nodes,"technology","Technology","TECH"); edge(edges,"target","technology","identified-as");}
            JSONArray redirects=evidence.optJSONArray("redirects"); if(redirects!=null){node(nodes,"redirects","Redirect chain","REDIRECT"); edge(edges,"target","redirects","redirects-to");}
            JSONObject content=evidence.optJSONObject("content"); if(content!=null){node(nodes,"content","Forms and content","CONTENT"); edge(edges,"target","content","contains");}
            JSONObject risk=evidence.optJSONObject("risk"); if(risk!=null){node(nodes,"risk",risk.optString("severity","UNKNOWN")+" risk","RISK"); edge(edges,"target","risk","assessed-as");}
            graph.put("nodes",nodes);graph.put("edges",edges);
        }catch(Exception ignored){} return graph;
    }
    public static JSONObject compare(JSONObject a, JSONObject b){JSONObject out=new JSONObject(); JSONArray changed=new JSONArray(); String[] keys={"dns","tls","http","technology","securityHeaders","content","risk","redirects"}; for(String k:keys) if(!a.optString(k,"{}").equals(b.optString(k,"{}"))) changed.put(k); try{out.put("changed",changed);out.put("from",a.optString("id","unknown"));out.put("to",b.optString("id","unknown"));}catch(Exception ignored){} return out;}
    private static void node(JSONArray n,String id,String label,String type)throws Exception{JSONObject o=new JSONObject();o.put("id",id);o.put("label",label);o.put("type",type);n.put(o);}
    private static void edge(JSONArray e,String from,String to,String relation)throws Exception{JSONObject o=new JSONObject();o.put("from",from);o.put("to",to);o.put("relation",relation);e.put(o);}
}
