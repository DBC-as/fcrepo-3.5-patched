
package org.fcrepo.server.security;

import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.fcrepo.server.errors.GeneralException;

import com.sun.xacml.PDPConfig;
import com.sun.xacml.attr.AttributeFactory;
import com.sun.xacml.attr.AttributeProxy;
import com.sun.xacml.combine.CombiningAlgFactory;
import com.sun.xacml.combine.CombiningAlgorithm;
import com.sun.xacml.cond.Function;
import com.sun.xacml.cond.FunctionFactory;
import com.sun.xacml.cond.FunctionFactoryProxy;
import com.sun.xacml.cond.FunctionProxy;
import com.sun.xacml.cond.cluster.FunctionCluster;
import com.sun.xacml.finder.AttributeFinderModule;
import com.sun.xacml.finder.PolicyFinderModule;
import com.sun.xacml.finder.ResourceFinderModule;

public interface PDPConfigurationFactory {

    public abstract AttributeFactory useStandardDatatypes();

    public abstract AttributeFactory useAttributeProxies(
            Map<String, AttributeProxy> proxies);

    public abstract CombiningAlgFactory useStandardAlgorithms();

    /**
     *
     * @param algorithms accepts a Set of CombiningAlgorithm impls
     * @return
     */

    public abstract CombiningAlgFactory useAlgorithms(
            Set<CombiningAlgorithm> algorithms);

    public abstract FunctionFactoryProxy useStandardFunctions();

    public abstract FunctionFactory useGeneralFunctions(
            Set<Function> functions, Map<String, FunctionProxy> proxies,
            List<FunctionCluster> clusters) throws URISyntaxException;

    public abstract FunctionFactory useConditionFunctions(
            FunctionFactory general, Set<Function> functions,
            Map<String, FunctionProxy> proxies, List<FunctionCluster> clusters)
            throws URISyntaxException;

    public abstract FunctionFactory useTargetFunctions(
            FunctionFactory conditions, Set<Function> functions,
            Map<String, FunctionProxy> proxies, List<FunctionCluster> clusters)
            throws URISyntaxException;

    public abstract FunctionFactoryProxy useFunctionFactories(
            FunctionFactory target, FunctionFactory condition,
            FunctionFactory general);

    public abstract PDPConfig getPDPConfig(
            List<AttributeFinderModule> attributeFinders,
            Set<PolicyFinderModule> policyFinders,
            List<ResourceFinderModule> resourceFinders);

    public abstract PDPConfig getDefaultPDPConfig() throws GeneralException;

}