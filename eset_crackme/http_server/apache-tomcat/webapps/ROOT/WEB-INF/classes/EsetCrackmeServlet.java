/*
    This servlet handles the remote call's HTTP request of
    the ESET crackme to successfully finish the last of its levels.
    
    (c) 2014 by Piotr Stolarz [pstolarz@o2.pl]
 */
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EsetCrackmeServlet extends HttpServlet
{
    private String xoredPswd = "!bw8";

    private static String HEX = "0123456789ABCDEF";

    private String encodeHex(byte[] in) {
        int i=0;
        byte[] out = new byte[2*in.length];
        for (byte b: in) {
            out[i++] = (byte)HEX.charAt((b>>4)&0x0f);
            out[i++] = (byte)HEX.charAt(b&0x0f);
        }
        return new String(out);
    }

    private byte[] prepareXorTab(byte[] initTab)
    {
        byte[] xorTab = new byte[0x102];

        for (int i=0; i<0x100; i++) xorTab[i]=(byte)i;

        for (int i=0,j=0,k=0; i<0x100; i++,j=(j+1)%initTab.length)
        {
            int newK = (xorTab[i]+initTab[j]+k) & 0xff;

            byte prevXi = xorTab[i];
            xorTab[i] = xorTab[newK];
            xorTab[newK] = prevXi;

            k = newK;
        }

        return xorTab;
    }

    private void xorWithTab(byte in[], byte xorTab[])
    {
        byte s = xorTab[0x100];
        byte d = xorTab[0x101];

        for (int i=0; i<in.length; i++)
        {
            s++;
            d = (byte)(d+xorTab[((int)s)&0xff]);

            byte prevXorTabS = xorTab[((int)s)&0xff];
            xorTab[((int)s)&0xff]=xorTab[((int)d)&0xff];
            xorTab[((int)d)&0xff]=prevXorTabS;

            in[i] ^= xorTab[((int)xorTab[((int)s)&0xff]+xorTab[((int)d)&0xff])&0xff];
        }
        xorTab[0x100] = s;
        xorTab[0x101] = d;
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
    {
        String keyVal = request.getParameter("key");

        if (keyVal!=null && keyVal.length()>0)
        {
            ServletOutputStream out = response.getOutputStream();
            response.setContentType("application/octet-stream");

            System.out.println("-> key=" + keyVal);

            byte[] xorTabKey = prepareXorTab(keyVal.getBytes());

            byte[] zeroTab = new byte[xorTabKey.length];
            Arrays.fill(zeroTab, (byte)0);

            xorWithTab(zeroTab, xorTabKey);

            byte[] pswd = xoredPswd.getBytes();
            byte[] resp = new byte[pswd.length];

            for (int i=0; i<resp.length && i<pswd.length; i++) {
                resp[i] = (byte)(zeroTab[i]^pswd[i]);
            }

            System.out.println("<- bytes[" + encodeHex(resp) + "]");

            out.write(resp);
        } else
        {
            /* The last crackme request with "r" param is not handled since
               it's wrongly encoded and causes problems on the HTTP server. */
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            out.println("<html><body>No <b>key</b> parameter provided!</body></html>");
        }
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
    {
        doGet(request, response);
    }
}
