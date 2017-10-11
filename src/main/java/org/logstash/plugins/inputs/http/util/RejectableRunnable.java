package org.logstash.plugins.inputs.http.util;

public abstract interface RejectableRunnable extends Runnable {
    public abstract void onRejection();
    public abstract void run();
}
