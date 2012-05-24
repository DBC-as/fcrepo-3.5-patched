
package org.fcrepo.server.security;

import java.util.List;

import org.fcrepo.server.Context;
import org.fcrepo.server.errors.authorization.AuthzException;

import com.sun.xacml.PDPConfig;

public interface PolicyEnforcementPoint {

    public static final String SUBACTION_SEPARATOR = "//";

    public static final String SUBRESOURCE_SEPARATOR = "//";

    public static final String ENFORCE_MODE_ENFORCE_POLICIES = "enforce-policies";

    public static final String ENFORCE_MODE_PERMIT_ALL_REQUESTS =
            "permit-all-requests";

    public static final String ENFORCE_MODE_DENY_ALL_REQUESTS = "deny-all-requests";

    public static final String XACML_SUBJECT_ID =
            "urn:oasis:names:tc:xacml:1.0:subject:subject-id";

    public static final String XACML_ACTION_ID =
            "urn:oasis:names:tc:xacml:1.0:action:action-id";

    public static final String XACML_RESOURCE_ID =
            "urn:oasis:names:tc:xacml:1.0:resource:resource-id";

    public void setAttributeFinderModules(
            List<com.sun.xacml.finder.AttributeFinderModule> attrFinderModules);

    public void setPDPConfig(PDPConfig pdpConfig);

    public void newPdp();

    public void inactivate();

    public void destroy();

    public void setEnforceMode(String mode);

    public void enforce(String subjectId, String action, String api,
            String pid, String namespace, Context context)
            throws AuthzException;

}
