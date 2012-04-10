
/*
 *
 */

package org.fcrepo.server.security.xacml.pdp.client;

import java.net.MalformedURLException;
import java.net.URL;

import javax.xml.namespace.QName;
import javax.xml.ws.Service;
import javax.xml.ws.WebEndpoint;
import javax.xml.ws.WebServiceClient;
import javax.xml.ws.WebServiceFeature;

/**
 * This class was generated by Apache CXF 2.4.0
 * 2011-08-01T16:22:54.509+02:00
 * Generated source version: 2.4.0
 *
 */


@WebServiceClient(name = "MelcoePDP",
                  targetNamespace = "http://pdp.xacml.melcoe")
public class MelcoePDP extends Service {

    public final static URL WSDL_LOCATION;

    public final static QName SERVICE = new QName("http://pdp.xacml.melcoe", "MelcoePDP");
    public final static QName MelcoePDPSOAP11PortHttp = new QName("http://pdp.xacml.melcoe", "MelcoePDPSOAP11port_http");
    static {
        URL url = null;
        try {
            url = new URL("file:./base/melcoe-pdp.wsdl");
        } catch (MalformedURLException e) {
            java.util.logging.Logger.getLogger(MelcoePDP.class.getName())
                .log(java.util.logging.Level.INFO,
                     "Can not initialize the default wsdl from {0}", "file:./base/melcoe-pdp.wsdl");
        }
        WSDL_LOCATION = url;
    }

    public MelcoePDP(URL wsdlLocation) {
        super(wsdlLocation, SERVICE);
    }

    public MelcoePDP(URL wsdlLocation, QName serviceName) {
        super(wsdlLocation, serviceName);
    }

    public MelcoePDP() {
        super(WSDL_LOCATION, SERVICE);
    }


    /**
     *
     * @return
     *     returns MelcoePDPPortType
     */
    @WebEndpoint(name = "MelcoePDPSOAP11port_http")
    public MelcoePDPPortType getMelcoePDPSOAP11PortHttp() {
        return super.getPort(MelcoePDPSOAP11PortHttp, MelcoePDPPortType.class);
    }

    /**
     *
     * @param features
     *     A list of {@link javax.xml.ws.WebServiceFeature} to configure on the proxy.  Supported features not in the <code>features</code> parameter will have their default values.
     * @return
     *     returns MelcoePDPPortType
     */
    @WebEndpoint(name = "MelcoePDPSOAP11port_http")
    public MelcoePDPPortType getMelcoePDPSOAP11PortHttp(WebServiceFeature... features) {
        return super.getPort(MelcoePDPSOAP11PortHttp, MelcoePDPPortType.class, features);
    }

}
