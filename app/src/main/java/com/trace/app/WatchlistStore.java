package com.trace.app;

import android.content.Context;
import android.content.SharedPreferences;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.List;

public final class WatchlistStore {
    private final SharedPreferences prefs;
    public WatchlistStore(Context c) { prefs=c.getSharedPreferences("trace_watchlist",Context.MODE_PRIVATE); }
    public synchronized void add(String target) { JSONArray a=allJson(); for(int i=0;i<a.length();i++) if(a.optString(i).equalsIgnoreCase(target)) return; a.put(target); prefs.edit().putString("targets",a.toString()).apply(); }
    public synchronized void remove(String target) { JSONArray old=allJson(), out=new JSONArray(); for(int i=0;i<old.length();i++) if(!old.optString(i).equalsIgnoreCase(target)) out.put(old.optString(i)); prefs.edit().putString("targets",out.toString()).apply(); }
    public synchronized List<String> all() { JSONArray a=allJson(); List<String> out=new ArrayList<>(); for(int i=0;i<a.length();i++)out.add(a.optString(i)); return out; }
    public synchronized void saveSnapshot(String target, JSONObject result) { prefs.edit().putString("snapshot:"+target,result.toString()).apply(); }
    public synchronized JSONObject snapshot(String target) { try{return new JSONObject(prefs.getString("snapshot:"+target,"{}"));}catch(Exception e){return new JSONObject();} }
    private JSONArray allJson(){try{return new JSONArray(prefs.getString("targets","[]"));}catch(Exception e){return new JSONArray();}}
}
