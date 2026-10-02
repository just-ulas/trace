package com.trace.app;

import android.content.Context;
import android.content.SharedPreferences;
import org.json.JSONObject;

/** Small local source registry; unavailable feeds remain UNKNOWN rather than becoming fake verdicts. */
public final class ThreatFeedCache {
    public enum Status { AVAILABLE, UNAVAILABLE, RATE_LIMITED, STALE, ERROR }
    private final SharedPreferences prefs;
    public ThreatFeedCache(Context c){prefs=c.getSharedPreferences("trace_feed_cache",Context.MODE_PRIVATE);}
    public JSONObject status(){JSONObject o=new JSONObject(); try{o.put("status",prefs.getString("status","UNAVAILABLE"));o.put("lastUpdated",prefs.getLong("updated",0));o.put("source","public keyless sources only");}catch(Exception ignored){} return o;}
    public void mark(String status){prefs.edit().putString("status",status).putLong("updated",System.currentTimeMillis()).apply();}
}
