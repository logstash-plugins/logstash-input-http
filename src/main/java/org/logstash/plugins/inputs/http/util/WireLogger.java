package org.logstash.plugins.inputs.http.util;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class WireLogger extends ChannelDuplexHandler {

    private final static Logger logger = LogManager.getLogger(WireLogger.class);

    public static final int MAX_DUMP_LENGTH = 4096;
    private static final int UNLIMITED_DUMP_LENGTH = 0;
    private static final String SIZE_PROP_NAME = "logstash.httpinput.wire.dump.size";
    private final int maxDumpLength;

    /**
     * Used to validate the dump's size system property. Has to be called before {@link #readDumpSizeProperty()}.
     * 
     * @throws RuntimeException if the number is not parseable as integer or if it's negative.
     * */
    public static void validateDumpSizeProperty() throws Exception {
        String dumpSizeStr = System.getProperty(SIZE_PROP_NAME, Integer.toString(MAX_DUMP_LENGTH));
        try {
            int dumpSize = Integer.parseInt(dumpSizeStr);
            if (dumpSize < 0) {
                throw new RuntimeException(SIZE_PROP_NAME + " system property has received negative integer value: " + dumpSize);
            }
        } catch (NumberFormatException e) {
            throw new RuntimeException(SIZE_PROP_NAME + " system property has received invalid integer value: " + dumpSizeStr, e);
        }
    }
    
    /**
     * Method used to retrieve the dump's size system property value. 
     * Doesn't check for validity, the {@link #validateDumpSizeProperty()} has to be called before.
     * 
     * @return integer value parsed from system property
     * @throws Exception throw any error that Integer.parseInt encounter.
     * */
    public static int readDumpSizeProperty() throws Exception {
        String dumpSizeStr = System.getProperty(SIZE_PROP_NAME, Integer.toString(MAX_DUMP_LENGTH));
        return Integer.parseInt(dumpSizeStr);
    }
    
    public WireLogger(int maxDumpLength) {
        this.maxDumpLength = maxDumpLength;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        if (logger.isDebugEnabled()) {
            logger.debug("Opening connection {}", ctx.channel().remoteAddress());
        }
        ctx.fireChannelActive();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        if (logger.isDebugEnabled()) {
            logger.debug("Closing connection {}", ctx.channel().remoteAddress());
        }
        ctx.fireChannelInactive();
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (logger.isDebugEnabled() && msg instanceof ByteBuf) {
            logger.debug("<< {} : {}", ctx.channel().remoteAddress(), dump((ByteBuf) msg, maxDumpLength));
        }
        ctx.fireChannelRead(msg);
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        if (logger.isDebugEnabled() && msg instanceof ByteBuf) {
            logger.debug(">> {} : {}", ctx.channel().remoteAddress(), dump((ByteBuf) msg, maxDumpLength));
        }
        ctx.write(msg, promise);
    }

    // maxLength == 0 means unlimited; any other value caps the dumped bytes and appends a truncation notice.
    static String dump(ByteBuf buf, int maxLength) {
        int total = buf.readableBytes();
        int limit = (maxLength == UNLIMITED_DUMP_LENGTH) ? total : Math.min(maxLength, total);

        StringBuilder sb = new StringBuilder();
        final int start = buf.readerIndex();
        final int end = start + limit;
        for (int i = start; i < end; i++) {
            byte b = buf.getByte(i);
            if (b == '\r') {
                sb.append("[\\r]");
            } else if (b == '\n') {
                sb.append("[\\n]");
            } else if (b >= 0x20 && b < 0x7F) {
                sb.append((char) b);
            } else {
                sb.append(String.format("[0x%02X]", b & 0xFF));
            }
        }

        if (maxLength > 0 && total > maxLength) {
            sb.append("...[truncated, total ").append(total).append(" bytes]");
        }

        return sb.toString();
    }
}
