/*
 * File: GetObjectHistoryFilter.java
 *
 * Copyright 2007 Macquarie E-Learning Centre Of Excellence
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.fcrepo.server.security.xacml.pep.rest.filters;

import java.io.IOException;

import java.net.URI;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.sun.xacml.attr.AnyURIAttribute;
import com.sun.xacml.attr.AttributeValue;
import com.sun.xacml.attr.StringAttribute;
import com.sun.xacml.ctx.RequestCtx;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.fcrepo.common.Constants;

import org.fcrepo.server.security.xacml.pep.PEPException;
import org.fcrepo.server.security.xacml.util.LogUtil;
import org.fcrepo.server.utilities.CXFUtility;


/**
 * Handles the getObjectHistory operation.
 *
 * @author nishen@melcoe.mq.edu.au
 */
public class GetObjectHistoryFilter
        extends AbstractFilter {

    private static final Logger logger =
            LoggerFactory.getLogger(GetObjectHistoryFilter.class);

    /**
     * Default constructor.
     *
     * @throws PEPException
     */
    public GetObjectHistoryFilter()
            throws PEPException {
        super();
    }

    /*
     * (non-Javadoc)
     * @see
     * org.fcrepo.server.security.xacml.pep.rest.filters.RESTFilter#handleRequest(javax.servlet
     * .http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    public RequestCtx handleRequest(HttpServletRequest request,
                                    HttpServletResponse response)
            throws IOException, ServletException {
        if (request.getPathInfo() == null) {
            logger.error("Bad request: " + request.getRequestURI());
            throw new ServletException("Bad request: "
                    + request.getRequestURI());
        }

        String[] parts = request.getPathInfo().split("/");
        if (parts.length < 2) {
            logger.info("Not enough path components on the URI.");
            throw new ServletException("Not enough path components on the URI.");
        }

        RequestCtx req = null;

        String pid = null;

        pid = parts[1];

        Map<URI, AttributeValue> actions = new HashMap<URI, AttributeValue>();
        Map<URI, AttributeValue> resAttr = new HashMap<URI, AttributeValue>();

        try {
            if (pid != null && !"".equals(pid)) {
                resAttr.put(Constants.OBJECT.PID.getURI(),
                            new StringAttribute(pid));
            }
            // XACML 1.0 conformance. resource-id is mandatory. Remove when
            // switching to 2.0
            if (pid != null && !"".equals(pid)) {
                resAttr
                        .put(new URI("urn:oasis:names:tc:xacml:1.0:resource:resource-id"),
                             new AnyURIAttribute(new URI(pid)));
            }

            actions.put(Constants.ACTION.ID.getURI(),
                        new StringAttribute(Constants.ACTION.GET_OBJECT_HISTORY
                                .getURI().toASCIIString()));
            actions.put(Constants.ACTION.API.getURI(),
                        new StringAttribute(Constants.ACTION.APIA.getURI()
                                .toASCIIString()));

            req =
                    getContextHandler().buildRequest(getSubjects(request),
                                                     actions,
                                                     resAttr,
                                                     getEnvironment(request));

            LogUtil.statLog(request.getRemoteUser(),
                            Constants.ACTION.GET_OBJECT_HISTORY.getURI()
                                    .toASCIIString(),
                            pid,
                            null);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            CXFUtility.getFault(e);
        }

        return req;
    }

    /*
     * (non-Javadoc)
     * @see
     * org.fcrepo.server.security.xacml.pep.rest.filters.RESTFilter#handleResponse(javax.servlet
     * .http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    public RequestCtx handleResponse(HttpServletRequest request,
                                     HttpServletResponse response)
            throws IOException, ServletException {
        return null;
    }
}
