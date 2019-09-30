package net.floodlightcontroller.linkverifier;

public class PortStat {

    public String portNumber; // 1,2,3 etc or "local"
    public long receivePackets;
    public long transmitPackets;
    public long receiveBytes;
    public long transmitBytes;
    public long receiveDropped;
    public long transmitDropped;
    public long receiveErrors;
    public long transmitErrors;
    public long receiveFrameErrors;
    public long receiveOverrunErrors;
    public long receiveCRCErrors;
    public long collisions;

    public PortStat() {
        // might need me later
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append("---------- port statistics --------");
        sb.append("\nport_number: ");
        sb.append(portNumber);
        sb.append("\nreceive_packets: ");
        sb.append(receivePackets);
        sb.append("\ntransmit_packets: ");
        sb.append(transmitPackets);
        sb.append("\nreceive_bytes: ");
        sb.append(receiveBytes);
        sb.append("\ntransmit_bytes: ");
        sb.append(transmitBytes);
        sb.append("\nreceive_dropped: ");
        sb.append(receiveDropped);
        sb.append("\ntransmit_dropped: ");
        sb.append(transmitDropped);
        sb.append("\nreceive_errors: ");
        sb.append(receiveErrors);
        sb.append("\ntransmit_errors: ");
        sb.append(transmitErrors);
        sb.append("\nreceive_frame_errors: ");
        sb.append(receiveFrameErrors);
        sb.append("\nreceive_overrun_errors: ");
        sb.append(receiveOverrunErrors);
        sb.append("\nreceive_CRC_errors: ");
        sb.append(receiveCRCErrors);
        sb.append("\ncollisions: ");
        sb.append(collisions);
        sb.append("\n---------- end --------");

        return sb.toString();
    }
}