package org.fcrepo.server.security.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.fcrepo.server.Server;
import org.fcrepo.server.config.ModuleConfiguration;
import org.fcrepo.server.errors.GeneralException;
import org.fcrepo.server.errors.ModuleInitializationException;
import org.fcrepo.server.security.PolicyParser;
import org.fcrepo.server.security.PolicyStrategy;
import org.fcrepo.server.storage.DOManager;
import org.fcrepo.server.validation.ValidationUtility;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.xacml.PDPConfig;
import com.sun.xacml.attr.AttributeFactory;
import com.sun.xacml.attr.AttributeProxy;
import com.sun.xacml.attr.BaseAttributeFactory;
import com.sun.xacml.attr.StandardAttributeFactory;
import com.sun.xacml.combine.BaseCombiningAlgFactory;
import com.sun.xacml.combine.CombiningAlgFactory;
import com.sun.xacml.combine.CombiningAlgorithm;
import com.sun.xacml.combine.StandardCombiningAlgFactory;
import com.sun.xacml.cond.BaseFunctionFactory;
import com.sun.xacml.cond.BasicFunctionFactoryProxy;
import com.sun.xacml.cond.Function;
import com.sun.xacml.cond.FunctionFactory;
import com.sun.xacml.cond.FunctionFactoryProxy;
import com.sun.xacml.cond.FunctionProxy;
import com.sun.xacml.cond.StandardFunctionFactory;
import com.sun.xacml.cond.cluster.FunctionCluster;
import com.sun.xacml.finder.AttributeFinder;
import com.sun.xacml.finder.AttributeFinderModule;
import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.PolicyFinderModule;
import com.sun.xacml.finder.ResourceFinder;
import com.sun.xacml.finder.ResourceFinderModule;

public class LegacyPDPConfigurationFactory extends PDPConfigurationFactory{

    private static final Logger logger =
            LoggerFactory.getLogger(LegacyPDPConfigurationFactory.class);

    private static final String REPOSITORY_POLICIES_DIRECTORY_KEY =
            "REPOSITORY-POLICIES-DIRECTORY";

    private static final String COMBINING_ALGORITHM_KEY = "XACML-COMBINING-ALGORITHM";

    private static final String POLICY_SCHEMA_PATH_KEY = "POLICY-SCHEMA-PATH";

    private static final String VALIDATE_REPOSITORY_POLICIES_KEY =
            "VALIDATE-REPOSITORY-POLICIES";

    private static final String VALIDATE_OBJECT_POLICIES_FROM_DATASTREAM_KEY =
            "VALIDATE-OBJECT-POLICIES-FROM-DATASTREAM";

    private List<AttributeFinderModule> m_attributeFinders = null;

    private final PolicyParser m_policyParser;

    private final DOManager m_manager;

    private final String m_serverHome;

    private PolicyStrategy m_policyStrategy;

    private String repositoryPoliciesActiveDirectory = "";

    private String combiningAlgorithm = "";

    private boolean validateRepositoryPolicies = false;

    private boolean validateObjectPoliciesFromDatastream = false;

    boolean enforceListObjectInFieldSearchResults = true;

    boolean enforceListObjectInResourceIndexResults = true;

    public LegacyPDPConfigurationFactory(Server server, DOManager manager, ModuleConfiguration authorizationConfig) throws ModuleInitializationException {
        try {
            m_serverHome =
                    server.getHomeDir().getCanonicalPath() + File.separator;
        } catch (IOException e1) {
            throw new ModuleInitializationException("couldn't get server home",
                                                    org.fcrepo.server.security.PDPConfigurationFactory.class.getName(),
                                                    e1);
        }


        m_manager = manager;

        Map<String, String> moduleParameters = authorizationConfig.getParameters();

        if (moduleParameters.containsKey(REPOSITORY_POLICIES_DIRECTORY_KEY)) {
            repositoryPoliciesActiveDirectory =
                    authorizationConfig.getParameter(REPOSITORY_POLICIES_DIRECTORY_KEY, true);
        }
        if (moduleParameters.containsKey(COMBINING_ALGORITHM_KEY)) {
            combiningAlgorithm =
                    moduleParameters.get(COMBINING_ALGORITHM_KEY);
        }

        // Initialize the policy parser given the POLICY_SCHEMA_PATH_KEY
        if (moduleParameters.containsKey(POLICY_SCHEMA_PATH_KEY)) {
            String schemaPath =
                    (moduleParameters.get(POLICY_SCHEMA_PATH_KEY)
                            .startsWith(File.separator) ? "" : m_serverHome)
                    + moduleParameters
                            .get(POLICY_SCHEMA_PATH_KEY);
            try {
                FileInputStream in = new FileInputStream(schemaPath);
                m_policyParser = new PolicyParser(in);
                ValidationUtility.setPolicyParser(m_policyParser);
            } catch (Exception e) {
                throw new ModuleInitializationException("Error loading policy schema: "
                                                        + schemaPath,
                                                        org.fcrepo.server.security.PDPConfigurationFactory.class.getName(),
                                                        e);
            }
        } else {
            throw new ModuleInitializationException("Policy schema path not specified.  Must be given as "
                                                    + POLICY_SCHEMA_PATH_KEY,
                                                    org.fcrepo.server.security.PDPConfigurationFactory.class.getName());
        }

        if (moduleParameters.containsKey(VALIDATE_REPOSITORY_POLICIES_KEY)) {
            validateRepositoryPolicies =
                    (new Boolean(moduleParameters
                            .get(VALIDATE_REPOSITORY_POLICIES_KEY)))
                            .booleanValue();
        }
        if (moduleParameters
                .containsKey(VALIDATE_OBJECT_POLICIES_FROM_DATASTREAM_KEY)) {
            try {
                validateObjectPoliciesFromDatastream =
                        Boolean.parseBoolean(moduleParameters
                                .get(VALIDATE_OBJECT_POLICIES_FROM_DATASTREAM_KEY));
            } catch (Exception e) {
                throw new ModuleInitializationException("bad init parm boolean value for "
                                                        + VALIDATE_OBJECT_POLICIES_FROM_DATASTREAM_KEY,
                                                        org.fcrepo.server.security.PDPConfigurationFactory.class.getName(),
                                                        e);
            }
        }
    }

    public void init() {
        if (m_policyStrategy == null) {
            m_policyStrategy = new AccumulatingPolicyStrategy(m_manager);
        }
    }

    public void setPolicyStrategy(PolicyStrategy policyStrategy) {
        m_policyStrategy = policyStrategy;
    }

    public void setAttributeFinderModules(List<AttributeFinderModule> attributeFinders) {
        m_attributeFinders = attributeFinders;
    }

    @Override
    public AttributeFactory useStandardDatatypes(){
        return StandardAttributeFactory.getNewFactory();
    }

    @Override
    public AttributeFactory useAttributeProxies(Map<String,AttributeProxy> proxies) {
        AttributeFactory result = new BaseAttributeFactory();
        for (String id:proxies.keySet()){
            result.addDatatype(id, proxies.get(id));
        }
        return result;
    }

    @Override
    public CombiningAlgFactory useStandardAlgorithms(){
        return StandardCombiningAlgFactory.getNewFactory();
    }

    /**
     *
     * @param algorithms accepts a Set of CombiningAlgorithm impls
     * @return
     */

    @Override
    public CombiningAlgFactory useAlgorithms(Set<CombiningAlgorithm> algorithms) {
        CombiningAlgFactory result = new BaseCombiningAlgFactory();
        for (CombiningAlgorithm algorithm: algorithms){
            result.addAlgorithm(algorithm);
        }
        return result;
    }

    @Override
    public FunctionFactoryProxy useStandardFunctions(){
        return StandardFunctionFactory.getNewFactoryProxy();
    }

    @Override
    public FunctionFactory useGeneralFunctions(Set<Function> functions,
            Map<String,FunctionProxy> proxies, List<FunctionCluster> clusters) throws URISyntaxException {
        return functionFactory(null,functions,proxies,clusters);
    }

    @Override
    public FunctionFactory useConditionFunctions(FunctionFactory general, Set<Function> functions,
            Map<String,FunctionProxy> proxies, List<FunctionCluster> clusters) throws URISyntaxException {
        return functionFactory(general,functions,proxies,clusters);
    }

    @Override
    public FunctionFactory useTargetFunctions(FunctionFactory conditions, Set<Function> functions,
            Map<String,FunctionProxy> proxies, List<FunctionCluster> clusters) throws URISyntaxException {
        return functionFactory(conditions,functions,proxies,clusters);
    }

    private FunctionFactory functionFactory(FunctionFactory base, Set<Function> functions,
            Map<String,FunctionProxy> proxies, List<FunctionCluster> clusters) throws URISyntaxException {
        FunctionFactory result = (base != null) ? new BaseFunctionFactory(base) : new BaseFunctionFactory();
        for (Function function:functions){
            result.addFunction(function);
        }

        for (String id:proxies.keySet()){
            result.addAbstractFunction(proxies.get(id), new URI(id));
        }

        for (FunctionCluster cluster:clusters){
            for (Object function:cluster.getSupportedFunctions()){
                result.addFunction((Function)function);
            }
        }
        return result;
    }

    @Override
    public FunctionFactoryProxy useFunctionFactories(FunctionFactory target, FunctionFactory condition, FunctionFactory general){
        FunctionFactoryProxy result = new BasicFunctionFactoryProxy(target, condition, general);
        return result;
    }

    @Override
    public PDPConfig getPDPConfig(List<AttributeFinderModule> attributeFinders,
                                  Set<PolicyFinderModule> policyFinders,
                                  List<ResourceFinderModule> resourceFinders) {
        AttributeFinder attr = new AttributeFinder();
        attr.setModules(attributeFinders);
        PolicyFinder policy = new PolicyFinder();
        policy.setModules(policyFinders);
        ResourceFinder rsrc = new ResourceFinder();
        rsrc.setModules(resourceFinders);
        return new PDPConfig(attr, policy, rsrc);
    }

    @Override
    public PDPConfig getDefaultPDPConfig() throws GeneralException {
        AttributeFinder attrFinder = new AttributeFinder();

        attrFinder.setModules(m_attributeFinders);
        logger.debug("before building policy finder");
        PolicyFinder policyFinder = new PolicyFinder();

        Set<com.sun.xacml.finder.PolicyFinderModule> policyModules =
                new HashSet<com.sun.xacml.finder.PolicyFinderModule>();
        PolicyFinderModule combinedPolicyModule = null;
        combinedPolicyModule =
                new org.fcrepo.server.security.PolicyFinderModule(combiningAlgorithm,
                                       m_serverHome,
                                       repositoryPoliciesActiveDirectory,
                                       validateRepositoryPolicies,
                                       validateObjectPoliciesFromDatastream,
                                       m_policyParser,
                                       m_policyStrategy);

        logger.debug("after constucting fedora policy finder module");
        logger.debug("before adding fedora policy finder module to policy finder hashset");
        policyModules.add(combinedPolicyModule);
        logger.debug("after adding fedora policy finder module to policy finder hashset");
        logger.debug("o before setting policy finder hashset into policy finder");
        policyFinder.setModules(policyModules);
        logger.debug("o after setting policy finder hashset into policy finder");
        return new PDPConfig(attrFinder, policyFinder, null);
    }

}