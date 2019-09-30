package net.floodlightcontroller.linkverifier;

import com.google.gson.annotations.SerializedName;

public class StatLink {
    @SerializedName("src-switch")
    public String src_switch;

    @SerializedName("src-port")
    public int src_port;

    @SerializedName("dst-switch")
    public String dst_switch;

    @SerializedName("dst-port")
    public int dst_port;

    public String type;
    public String direction;
    public int latency;

    public StatLink() {
        // add stuff later
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("--------- link description ---------\n");
        sb.append("src-switch: ");
        sb.append(src_switch);
        sb.append("\nsrc-port: ");
        sb.append(src_port);
        sb.append("\ndst-switch: ");
        sb.append(dst_switch);
        sb.append("\ndst-port: ");
        sb.append(dst_port);
        sb.append("\ntype: ");
        sb.append(type);
        sb.append("\ndirection: ");
        sb.append(direction);
        sb.append("\nlatency: ");
        sb.append(latency);
        sb.append("\n----- link description  end -----");

        return sb.toString();

    }
}
