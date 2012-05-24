/* The contents of this file are subject to the license and copyright terms
 * detailed in the license directory at the root of the source tree (also
 * available online at http://fedora-commons.org/license/).
 */
package org.fcrepo.server.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.fcrepo.common.Constants;
import org.fcrepo.common.FaultException;
import org.fcrepo.server.errors.GeneralException;
import org.fcrepo.utilities.FileUtils;
import org.fcrepo.utilities.XmlTransformUtility;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.xacml.AbstractPolicy;
import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.PolicySet;
import com.sun.xacml.attr.AttributeValue;
import com.sun.xacml.attr.BagAttribute;
import com.sun.xacml.attr.StringAttribute;
import com.sun.xacml.combine.PolicyCombiningAlgorithm;
import com.sun.xacml.cond.EvaluationResult;
import com.sun.xacml.ctx.Status;
import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.PolicyFinderResult;

/**
 * XACML PolicyFinder for Fedora.
 * <p>
 * This provides repository-wide policies and object-specific policies,
 * when available.
 */
public class PolicyFinderModule
        extends com.sun.xacml.finder.PolicyFinderModule {

    private static final Logger logger =
            LoggerFactory.getLogger(PolicyFinderModule.class);

    private static final String XACML_DIST_BASE = "fedora-internal-use";

    private static final String DEFAULT = "default";

    private static final String DEFAULT_REPOSITORY_POLICIES_DIRECTORY =
            XACML_DIST_BASE
            + "/fedora-internal-use-repository-policies-approximating-2.0";

    private static final String BE_SECURITY_XML_LOCATION =
            "config/beSecurity.xml";

    private static final String BACKEND_POLICIES_ACTIVE_DIRECTORY =
            XACML_DIST_BASE + "/fedora-internal-use-backend-service-policies";

    private static final String BACKEND_POLICIES_XSL_LOCATION =
            XACML_DIST_BASE + "/build-backend-policy.xsl";

    private static final List<String> ERROR_CODE_LIST = new ArrayList<String>(1);

    static {
        ERROR_CODE_LIST.add(Status.STATUS_PROCESSING_ERROR);
    }

    private final String m_combiningAlgorithm;

    private final String m_defaultRepositoryPoliciesDirectoryPath;

    private final String m_repositoryBackendPolicyDirectoryPath;

    private final String m_repositoryPolicyDirectoryPath;

    private final String m_repositoryBackendXSLLocation;

    private final String m_repositoryBackendSecurityXMLLocation;

    private final boolean m_validateRepositoryPolicies;

    private final boolean m_validateObjectPoliciesFromDatastream;

    private final PolicyParser m_policyParser;

    private final PolicyStrategy m_policyStrategy;

    private Collection<AbstractPolicy> m_repositoryPolicies;

    public PolicyFinderModule(String combiningAlgorithm,
                              String serverHome,
                              String repositoryPolicyDirectoryPath,
                              boolean validateRepositoryPolicies,
                              boolean validateObjectPoliciesFromDatastream,
                              PolicyParser policyParser,
                              PolicyStrategy policyStrategy)
            throws GeneralException {

        m_combiningAlgorithm = combiningAlgorithm;
        m_repositoryPolicyDirectoryPath = repositoryPolicyDirectoryPath;

        m_repositoryBackendPolicyDirectoryPath = serverHome + File.separator
                + BACKEND_POLICIES_ACTIVE_DIRECTORY;

        m_repositoryBackendXSLLocation = serverHome + File.separator
                + BACKEND_POLICIES_XSL_LOCATION;

        m_repositoryBackendSecurityXMLLocation = serverHome + File.separator
                + BE_SECURITY_XML_LOCATION;

        m_defaultRepositoryPoliciesDirectoryPath = serverHome + File.separator
                + DEFAULT_REPOSITORY_POLICIES_DIRECTORY;

        m_validateRepositoryPolicies = validateRepositoryPolicies;
        m_validateObjectPoliciesFromDatastream = validateObjectPoliciesFromDatastream;
        m_policyParser = policyParser;
        m_policyStrategy = policyStrategy;
    }

    /**
     * Does nothing at init time.
     */
    @Override
    public void init(PolicyFinder finder) {
        logger.info("Loading repository policies...");
        try {
            setupActivePolicyDirectories();
            Map<String,AbstractPolicy> repositoryPolicies =
                    m_policyStrategy.loadPolicies(m_policyParser,
                    m_validateRepositoryPolicies,
                    new File(m_repositoryBackendPolicyDirectoryPath));
            repositoryPolicies.putAll(
                    m_policyStrategy.loadPolicies(m_policyParser,
                                 m_validateRepositoryPolicies,
                                 new File(m_repositoryPolicyDirectoryPath)));
            m_repositoryPolicies = repositoryPolicies.values();
        } catch (Exception e) {
            logger.error(e.toString(),e);
            throw new RuntimeException("Error loading repository policies", e); // alas, no exception in signature
        }
    }

    /**
     * Always returns true, indicating that this impl supports finding policies
     * based on a request.
     */
    @Override
    public boolean isRequestSupported() {
        return true;
    }

    /**
     * Gets a deny-biased policy set that includes all repository-wide and
     * object-specific policies.
     */
    @Override
    public PolicyFinderResult findPolicy(EvaluationCtx context) {
        PolicyFinderResult policyFinderResult = null;
        try {
            List<AbstractPolicy> policies = new ArrayList<AbstractPolicy>(m_repositoryPolicies);
            String pid = getPid(context);
            if (pid != null && !"".equals(pid)) {
                AbstractPolicy objectPolicyFromObject = m_policyStrategy.loadObjectPolicy(m_policyParser.copy(), pid, m_validateObjectPoliciesFromDatastream);
                if (objectPolicyFromObject != null) {
                    policies.add(objectPolicyFromObject);
                }
            }
            PolicyCombiningAlgorithm policyCombiningAlgorithm =
                    (PolicyCombiningAlgorithm) Class
                            .forName(m_combiningAlgorithm).newInstance();
            PolicySet policySet =
                    new PolicySet(new URI(""),
                                  policyCombiningAlgorithm,
                                  null /*
                                   * no general target beyond those of
                                   * multiplexed individual policies
                                   */,
                                  policies);
            policyFinderResult = new PolicyFinderResult(policySet);
        } catch (Exception e) {
            logger.warn("PolicyFinderModule seriously failed to evaluate a policy ", e);
            policyFinderResult =
                    new PolicyFinderResult(new Status(ERROR_CODE_LIST, e
                            .getMessage()));
        }
        return policyFinderResult;
    }

    // get the pid from the context, or null if unable
    public static String getPid(EvaluationCtx context) {
        URI resourceIdType = null;
        URI resourceIdId = null;
        try {
            resourceIdType = new URI(StringAttribute.identifier);
            resourceIdId = new URI(Constants.OBJECT.PID.uri);
        } catch (URISyntaxException e) {
            throw new FaultException("Bad URI syntax", e);
        }
        EvaluationResult attribute
                = context.getResourceAttribute(resourceIdType,
                                               resourceIdId,
                                               null);
        Object element = getAttributeFromEvaluationResult(attribute);
        if (element == null) {
            logger.debug("PolicyFinderModule:getPid exit on "
                    + "can't get contextId on request callback");
            return null;
        }

        if (!(element instanceof StringAttribute)) {
            logger.debug("PolicyFinderModule:getPid exit on "
                    + "couldn't get contextId from xacml request "
                    + "non-string returned");
            return null;
        }

        return ((StringAttribute) element).getValue();
    }

    // copy of code in AttributeFinderModule; consider refactoring
    private static final Object getAttributeFromEvaluationResult(EvaluationResult attribute) {
        if (attribute.indeterminate()) {
            return null;
        }

        if (attribute.getStatus() != null
                && !Status.STATUS_OK.equals(attribute.getStatus())) {
            return null;
        }

        AttributeValue attributeValue = attribute.getAttributeValue();
        if (!(attributeValue instanceof BagAttribute)) {
            return null;
        }

        BagAttribute bag = (BagAttribute) attributeValue;
        if (1 != bag.size()) {
            return null;
        } else {
            return bag.iterator().next();
        }
    }

    private void setupActivePolicyDirectories() throws Exception {
        FileUtils.copy(new File(m_defaultRepositoryPoliciesDirectoryPath),
                new File(m_repositoryPolicyDirectoryPath + File.separator + DEFAULT));
        generateBackendPolicies();
    }

    private final void generateBackendPolicies() throws Exception {
        File backendPoliciesDirectory = new File(m_repositoryBackendPolicyDirectoryPath);
        if (!backendPoliciesDirectory.exists()) backendPoliciesDirectory.mkdirs();
        else FileUtils.deleteFiles(backendPoliciesDirectory);
        BackendPolicies backendPolicies =
                new BackendPolicies(m_repositoryBackendSecurityXMLLocation);
        Hashtable<String, String> tempfiles = backendPolicies.generateBackendPolicies();
        TransformerFactory tfactory = XmlTransformUtility.getTransformerFactory();
        try {
            Iterator<String> iterator = tempfiles.keySet().iterator();
            while (iterator.hasNext()) {
                File f =
                        new File(m_repositoryBackendXSLLocation); // <<stylesheet
                // location
                StreamSource ss = new StreamSource(f);
                Transformer transformer = tfactory.newTransformer(ss); // xformPath
                String key = iterator.next();
                File infile = new File(tempfiles.get(key));
                FileInputStream fis = new FileInputStream(infile);
                FileOutputStream fos =
                        new FileOutputStream(m_repositoryBackendPolicyDirectoryPath
                                             + File.separator + key);
                transformer.transform(new StreamSource(fis),
                                      new StreamResult(fos));
            }
        } finally {
            // we're done with temp files now, so delete them
            Iterator<String> iter = tempfiles.keySet().iterator();
            while (iter.hasNext()) {
                File tempFile = new File(tempfiles.get(iter.next()));
                tempFile.delete();
            }
        }
    }
}
