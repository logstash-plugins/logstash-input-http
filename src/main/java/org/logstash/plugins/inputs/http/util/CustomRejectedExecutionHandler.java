package org.logstash.plugins.inputs.http.util;

import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;

public class CustomRejectedExecutionHandler implements RejectedExecutionHandler{

    @Override
    public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {
        if (r instanceof RejectableRunnable) {
            ((RejectableRunnable) r).onRejection();
        }
    }
}
