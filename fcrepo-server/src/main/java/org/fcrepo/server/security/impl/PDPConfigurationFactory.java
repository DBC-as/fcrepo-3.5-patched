package org.fcrepo.server.security.impl;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.fcrepo.server.errors.GeneralException;

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

public class PDPConfigurationFactory implements org.fcrepo.server.security.PDPConfigurationFactory {

    public PDPConfigurationFactory() {
    }

    /* (non-Javadoc)
     * @see org.fcrepo.server.security.PDPConfigurationFactory#useStandardDatatypes()
     */
    @Override
    public AttributeFactory useStandardDatatypes(){
        return StandardAttributeFactory.getNewFactory();
    }

    /* (non-Javadoc)
     * @see org.fcrepo.server.security.PDPConfigurationFactory#useAttributeProxies(java.util.Map)
     */
    @Override
    public AttributeFactory useAttributeProxies(Map<String,AttributeProxy> proxies) {
        AttributeFactory result = new BaseAttributeFactory();
        for (String id:proxies.keySet()){
            result.addDatatype(id, proxies.get(id));
        }
        return result;
    }

    /* (non-Javadoc)
     * @see org.fcrepo.server.security.PDPConfigurationFactory#useStandardAlgorithms()
     */
    @Override
    public CombiningAlgFactory useStandardAlgorithms(){
        return StandardCombiningAlgFactory.getNewFactory();
    }

    /* (non-Javadoc)
     * @see org.fcrepo.server.security.PDPConfigurationFactory#useAlgorithms(java.util.Set)
     */

    @Override
    public CombiningAlgFactory useAlgorithms(Set<CombiningAlgorithm> algorithms) {
        CombiningAlgFactory result = new BaseCombiningAlgFactory();
        for (CombiningAlgorithm algorithm: algorithms){
            result.addAlgorithm(algorithm);
        }
        return result;
    }

    /* (non-Javadoc)
     * @see org.fcrepo.server.security.PDPConfigurationFactory#useStandardFunctions()
     */
    @Override
    public FunctionFactoryProxy useStandardFunctions(){
        return StandardFunctionFactory.getNewFactoryProxy();
    }

    /* (non-Javadoc)
     * @see org.fcrepo.server.security.PDPConfigurationFactory#useGeneralFunctions(java.util.Set, java.util.Map, java.util.List)
     */
    @Override
    public FunctionFactory useGeneralFunctions(Set<Function> functions,
            Map<String,FunctionProxy> proxies, List<FunctionCluster> clusters) throws URISyntaxException {
        return functionFactory(null,functions,proxies,clusters);
    }

    /* (non-Javadoc)
     * @see org.fcrepo.server.security.PDPConfigurationFactory#useConditionFunctions(com.sun.xacml.cond.FunctionFactory, java.util.Set, java.util.Map, java.util.List)
     */
    @Override
    public FunctionFactory useConditionFunctions(FunctionFactory general, Set<Function> functions,
            Map<String,FunctionProxy> proxies, List<FunctionCluster> clusters) throws URISyntaxException {
        return functionFactory(general,functions,proxies,clusters);
    }

    /* (non-Javadoc)
     * @see org.fcrepo.server.security.PDPConfigurationFactory#useTargetFunctions(com.sun.xacml.cond.FunctionFactory, java.util.Set, java.util.Map, java.util.List)
     */
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

    /* (non-Javadoc)
     * @see org.fcrepo.server.security.PDPConfigurationFactory#useFunctionFactories(com.sun.xacml.cond.FunctionFactory, com.sun.xacml.cond.FunctionFactory, com.sun.xacml.cond.FunctionFactory)
     */
    @Override
    public FunctionFactoryProxy useFunctionFactories(FunctionFactory target, FunctionFactory condition, FunctionFactory general){
        FunctionFactoryProxy result = new BasicFunctionFactoryProxy(target, condition, general);
        return result;
    }

    /* (non-Javadoc)
     * @see org.fcrepo.server.security.PDPConfigurationFactory#getPDPConfig(java.util.List, java.util.Set, java.util.List)
     */
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

    /* (non-Javadoc)
     * @see org.fcrepo.server.security.PDPConfigurationFactory#getDefaultPDPConfig()
     */
    @Override
    public PDPConfig getDefaultPDPConfig() throws GeneralException {
        List<AttributeFinderModule> attributeFinders = new ArrayList<AttributeFinderModule>();
        Set<PolicyFinderModule> policyFinders = new HashSet<PolicyFinderModule>();
        List<ResourceFinderModule> resourceFinders = new ArrayList<ResourceFinderModule>();
        // defaults?
        return getPDPConfig(attributeFinders, policyFinders, resourceFinders);
    }

}