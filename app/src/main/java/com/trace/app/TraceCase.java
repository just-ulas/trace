package com.trace.app;

import org.json.JSONException;
import org.json.JSONObject;

/** A persisted, local-first TRACE investigation case. */
public final class TraceCase {
    public final String id;
    public final String target;
    public final String timestamp;
    public final String resultsJson;

    public TraceCase(String id, String target, String timestamp, String resultsJson) {
        this.id = id;
        this.target = target;
        this.timestamp = timestamp;
        this.resultsJson = resultsJson;
    }

    public JSONObject toJson() throws JSONException {
        JSONObject object = new JSONObject();
        object.put("id", id);
        object.put("target", target);
        object.put("timestamp", timestamp);
        object.put("results", new JSONObject(resultsJson));
        return object;
    }

    public static TraceCase fromJson(JSONObject object) throws JSONException {
        return new TraceCase(
                object.optString("id", "CASE-00000"),
                object.optString("target", "unknown"),
                object.optString("timestamp", ""),
                object.optJSONObject("results") == null
                        ? "{}"
                        : object.optJSONObject("results").toString());
    }
}
