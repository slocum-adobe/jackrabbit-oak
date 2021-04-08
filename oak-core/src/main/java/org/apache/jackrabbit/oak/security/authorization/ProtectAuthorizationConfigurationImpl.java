package org.apache.jackrabbit.oak.security.authorization;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.jcr.security.AccessControlManager;

import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.plugins.memory.MemoryNodeStore;
import org.apache.jackrabbit.oak.security.authorization.protect.CugAccessControlManager;
import org.apache.jackrabbit.oak.security.authorization.protect.ProtectPermissionProvider;
import org.apache.jackrabbit.oak.security.authorization.permission.AllPermissionProviderImpl;
import org.apache.jackrabbit.oak.security.authorization.permission.PermissionUtil;
import org.apache.jackrabbit.oak.spi.commit.MoveTracker;
import org.apache.jackrabbit.oak.spi.lifecycle.RepositoryInitializer;
import org.apache.jackrabbit.oak.spi.mount.MountInfoProvider;
import org.apache.jackrabbit.oak.spi.mount.Mounts;
import org.apache.jackrabbit.oak.spi.namespace.NamespaceConstants;
import org.apache.jackrabbit.oak.spi.nodetype.NodeTypeConstants;
import org.apache.jackrabbit.oak.spi.security.ConfigurationBase;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;
import org.apache.jackrabbit.oak.spi.security.Context;
import org.apache.jackrabbit.oak.spi.security.SecurityConfiguration;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.AuthorizationConfiguration;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.jackrabbit.oak.spi.state.ApplyDiff;
import org.apache.jackrabbit.oak.spi.state.NodeBuilder;
import org.apache.jackrabbit.oak.spi.state.NodeState;
import org.apache.jackrabbit.oak.spi.state.NodeStore;
import org.apache.jackrabbit.oak.spi.xml.ImportBehavior;
import org.jetbrains.annotations.NotNull;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.osgi.service.metatype.annotations.Option;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import adobe.protect.core.secure.access.api.ProtectOverrideRule;
import adobe.protect.core.secure.access.api.ProtectRule;

import org.osgi.service.component.annotations.ReferencePolicy;

import static org.apache.jackrabbit.oak.spi.security.RegistrationConstants.OAK_SECURITY_NAME;

/**
 * Custom implementation of the {@code AccessControlConfiguration}.
 */
@Component(
        service = {AuthorizationConfiguration.class, SecurityConfiguration.class},
        property = OAK_SECURITY_NAME + "=org.apache.jackrabbit.oak.security.authorization.ProtectAuthorizationConfigurationImpl",
        reference = {
			               
		                @Reference(
		                        name = "protectOverrideRule",
		                        bind = "bindProtectOverrideRule",
		                        unbind = "unbindProtectOverrideRule",
		                        service = ProtectOverrideRule.class,
		                        policy = ReferencePolicy.DYNAMIC,
		                        cardinality = ReferenceCardinality.MULTIPLE
		                ),
		                @Reference(
		                        name = "protectRule",
		                        bind = "bindProtectRule",
		                        unbind = "unbindProtectRule",
		                        service = ProtectRule.class,
		                        policy = ReferencePolicy.DYNAMIC,
		                        cardinality = ReferenceCardinality.MULTIPLE
		                )
		}
)
@Designate(ocd = ProtectAuthorizationConfigurationImpl.Configuration.class)
public class ProtectAuthorizationConfigurationImpl extends ConfigurationBase implements AuthorizationConfiguration, ProviderCtx {

    @ObjectClassDefinition(name = "Apache Jackrabbit Oak extension - ProtectAuthorizationConfiguration")
    @interface Configuration {
        @AttributeDefinition(
                name = "Jackrabbit 2.x Permissions",
                description = "Enforce backwards compatible permission validation with respect to the configurable options.",
                cardinality = 2,
                options = {
                        @Option(label = "USER_MANAGEMENT", value = "USER_MANAGEMENT"),
                        @Option(label = "REMOVE_NODE", value = "REMOVE_NODE")
                })
        String permissionsJr2();
        @AttributeDefinition(
                name = "Import Behavior",
                description = "Behavior for access control related items upon XML import.",
                options = {
                        @Option(label = ImportBehavior.NAME_ABORT, value = ImportBehavior.NAME_ABORT),
                        @Option(label = ImportBehavior.NAME_BESTEFFORT, value = ImportBehavior.NAME_BESTEFFORT),
                        @Option(label = ImportBehavior.NAME_IGNORE, value = ImportBehavior.NAME_IGNORE)
                })
        String importBehavior() default ImportBehavior.NAME_BESTEFFORT;

        @AttributeDefinition(
                name = "Readable Paths",
                description = "Enable full read access to regular nodes and properties at the specified paths irrespective of other policies that may take effective.")
        String[] readPaths() default {
                NamespaceConstants.NAMESPACES_PATH,
                NodeTypeConstants.NODE_TYPES_PATH,
                PrivilegeConstants.PRIVILEGES_PATH };

        @AttributeDefinition(
                name = "Administrative Principals",
                description = "Allows to specify principals that should be granted full permissions on the complete repository content.",
                cardinality = 300)
        String[] administrativePrincipals() default {
        	"admin","account-manager","acs-commons-automatic-package-replicator-service","acs-commons-bulk-workflow-service","acs-commons-component-error-handler-service",
        	"acs-commons-dispatcher-flush-service","acs-commons-email-service","acs-commons-ensure-oak-index-service","acs-commons-ensure-service-user-service",
        	"acs-commons-error-page-handler-service","acs-commons-file-fetch-service","acs-commons-form-helper-service","acs-commons-httpcache-jcr-storage-service",
        	"acs-commons-manage-controlled-processes-service","acs-commons-manage-redirects-service","acs-commons-on-deploy-scripts-service",
        	"acs-commons-package-replication-status-event-service","acs-commons-remote-assets-service","acs-commons-review-task-asset-mover-service",
        	"acs-commons-shared-component-props-service","acs-commons-system-notifications-service","acs-commons-twitter-updater-service","acs-commons-workflow-remover-service",
        	"acs-commons-workflowpackagemanager-service","activity-service","activitypurgesrv","analytics-content-updater-service","analyticsservice","assetdownloadservice",
        	"assetlinkshareservice","assetusagetrackeruser","async-jobs-service","audit-service","authentication-service","author-publish-screens-service",
        	"brandportal-imsconfig-service","bulk-offline-update-screens-service","campaign-cloudservice","campaign-property-modification-service","campaign-reader",
        	"canvaspage-activate-service","canvaspage-delete-service","cdn-service","clientlibs-service","cloudconfig-scripttags","commerce-backend-service",
        	"commerce-orders-service","communities-acl-manager","communities-analytics-admin","communities-enablement-property-writer","communities-srp-config-reader",
        	"communities-tag-admin","communities-ugc-writer","communities-user-admin","communities-utility-reader","compat-codeupgrade-service","configuration-reader-service",
        	"content-acreader-service","content-reader-service","content-writer-service","contentsync-service","contexthub-cache-service","contexthub-conf-reader",
        	"cryptoservice","cug-service","dam-activitywriter-service","dam-formitemseditor-service","dam-metadata-export-service","dam-reader-service",
        	"dam-replication-service","dam-reports-manager-service","dam-teammgr-service","dam-update-service","dam-writer-service","design-cache-service",
        	"dtm-reactor-imsconfig-service","dtm-reactor-service","dtmservice","dynamic-media-replication","dynamic-media-replication-filter","dynamic-media-s7sync",
        	"dynamicmedia-config-service","experience-fragments-service","fd-cloudservice","fd-service","fontconfig-service","foundation-forms-service",
        	"foundation-forms-store-service","granite-async-jobs-service","group-administration-service","group-reader-service","idsjobprocessor","index-admin",
        	"language-manager-service","launch-event-service","launch-promote-service","linkstorage-service","monitoring-screens-service","monitoringScripts",
        	"msm-service","namespace-mgmt-service","nlp-reader","notification-service","nui-process-service","oauthservice","offloading-agentmanager","offloading-jobcloner",
        	"offloading-service","omnisearch-service","on-off-time-service","packagelist-service","page-name-validator-service","pageexporterservice",
        	"polling-importer-service","primary-resource-search-service","projects-purge-service","projects-service","recs-deleted-products-listener-service",
        	"reference-adjustment-service","reference-processing-service","remote-ref-cache-user","replication-service","repository-change-listener-service",
        	"repository-reader-service","resourcecollectionservice","root-reader-service","s7dam-config-service","scene7-config-service","scene7-config-writer-service",
        	"scheduled-exporter-service","screens-group-admin-service","searchpromote-service","security-userproperties-service","service-admin",
        	"sling-context-aware-config-web-console","sling-discovery","sling-distribution","sling-event","sling-installer-service","sling-jcr-install","sling-scripting",
        	"sling-tenant","sling-xss","snapshotservice","social-enablement-replication-user","social-enablement-tmp-manager","spellchecker-service","ssl-service",
        	"statistics-service","stock-imsconfig-service","tag-garbage-collection-service","tag-validation-service","target-imsconfig-service","targetservice",
        	"taskmanagement-service","translation-config-service","translation-job-service","translation-preview-service","truststore-reader-service","undo-service",
        	"user-administration-service","user-reader-service","version-manager-service","version-purge-service","versions-preview-service-user","wcm-workflow-service",
        	"webdavbkpservice","webservice-support-replication","webservice-support-servicelibfinder","workflow-process-service","workflow-service","wurfl-loader-service",
        	"youtube-authenticator-user"
        };

        @AttributeDefinition(
                name = "Ranking",
                description = "Ranking of this configuration in a setup with multiple authorization configurations.")
        int configurationRanking() default 140;
        
         @AttributeDefinition(name = "protectRuleService",
	              description = "Attribute Based Access Control Protection Rules Registration")
	     String[] protect_rules_service();
	      
	     @AttributeDefinition(name = "protectOverrideRuleService",
	              description = "Attribute Based Access Control Protection Override Rules Registration")
	     String[] protect_override_rules_service() default {"adobe.protect.core.secure.rules.IsTheAuthor"}; 
    }

    private static final Logger log = LoggerFactory.getLogger("adobe.protect");
    
    private String[] protectRuleServiceConfiguration;
	private String[] protectOverrideRuleServiceConfiguration;
	
	/** Bound via OSGi */
	private Map<String, ProtectOverrideRule> protectOverrideRules = new ConcurrentHashMap<>();
	
	/** Bound via OSGi */
	private Map<String, ProtectRule> protectRules = new ConcurrentHashMap<>();
    
    private MountInfoProvider mountInfoProvider = Mounts.defaultMountInfoProvider();

    
    /** 
	 * Bind & Unbind methods for ProtectOverrideRule
	 * All classes deployed to AEM instance that implement ProtectOverrideRule should be bound
	 */
    protected final void bindProtectOverrideRule(final ProtectOverrideRule service, final Map<Object, Object> props) {
        final String type = service.getClass().getName();
        if (type != null) {
        	log.debug("Bind Protect Override Rule: {} ", type);
            this.protectOverrideRules.put(type, service);
        }
    }

    protected final void unbindProtectOverrideRule(final ProtectOverrideRule service, final Map<Object, Object> props) {
        final String type = service.getClass().getName();
        if (type != null) {
        	log.debug("Unbind Protect Override Rule: {} ", type);
            this.protectOverrideRules.remove(type);
        }
    }

    /** 
	 * Bind & Unbind methods for ProtectRule
	 * All classes deployed to AEM instance that implement ProtectRule should be bound
	 */
    protected final void bindProtectRule(final ProtectRule service, final Map<Object, Object> props) {
        final String type = service.getClass().getName();
        log.debug("Bind Protect Rule: {} ", type);
        if (type != null) {
            this.protectRules.put(type, service);
        }
    }

    protected final void unbindProtectRule(final ProtectRule service, final Map<Object, Object> props) {
        final String type = service.getClass().getName();
        if (type != null) {
        	log.debug("Unbind Protect Rule: {} ", type);
            this.protectRules.remove(type);
        }
    }
    /** End Bind & Unbind methods */
    
    private Map<String, ProtectOverrideRule> getRegisteredProtectOverrideRules(){
    	if(protectOverrideRuleServiceConfiguration == null || protectOverrideRuleServiceConfiguration.length == 0){
    		return null;
    	}
    	Map<String, ProtectOverrideRule> newMap = new ConcurrentHashMap<>();
    	for (String string : protectOverrideRuleServiceConfiguration) {
    		try
    		{
    			newMap.put(string, protectOverrideRules.get(string));
    		} catch (Exception ex){
    			log.debug("Could not register Protect Override Rule {} {} ", string, ex);
    		}
		}
    	return newMap;    	
    }
    
    private Map<String, ProtectRule> getRegisteredProtectRules(){
    	if(protectRuleServiceConfiguration == null || protectRuleServiceConfiguration.length == 0){
    		return null;
    	}
    	
    	Map<String, ProtectRule> newMap = new ConcurrentHashMap<>();
    	for (String string : protectRuleServiceConfiguration) {
    		try
    		{
    			newMap.put(string, protectRules.get(string));
    		} catch (Exception ex){
    			log.debug("Could not register Protect Rule {} {} ", string, ex);
    		}
		}
    	return newMap;    	
    }
    
    public ProtectAuthorizationConfigurationImpl() {
        super();
    }

    public ProtectAuthorizationConfigurationImpl(@NotNull SecurityProvider securityProvider) {
        super(securityProvider, securityProvider.getParameters(NAME));
    }

    /**
     * All configured protect.rules.service and protect.override.rules.service MUST be a satisfied bound 
     * service ID of this components associated Referenced service
     * 
     * Reference to @Configuration class needed for correct DS xml generation
    */
    @Activate
        private void activate(Configuration configuration, Map properties) {
        setParameters(ConfigurationParameters.of(properties));
        log.debug("Set configured Protect Rule and Protect Override Rule properties");
    	protectRuleServiceConfiguration = configuration.protect_rules_service();
    	protectOverrideRuleServiceConfiguration = configuration.protect_override_rules_service();
    }

    //----------------------------------------------< SecurityConfiguration >---
    @NotNull
    @Override
    public String getName() {
        return NAME;
    }

    @NotNull
    @Override
    public Context getContext() {
    	return Context.DEFAULT; 
    }
    
    @NotNull
    @Override
    public RepositoryInitializer getRepositoryInitializer() {
    	return new RepositoryInitializer() {
			@Override
			public void initialize(@NotNull NodeBuilder builder) {
                NodeState base = builder.getNodeState();
                NodeStore store = new MemoryNodeStore(base);
                NodeState target = store.getRoot();
                target.compareAgainstBaseState(base, new ApplyDiff(builder));
				
			}
        };
    }

    @NotNull
    @Override
    public List getCommitHooks(@NotNull String workspaceName) {
    	return super.getCommitHooks(workspaceName);
    }

    @NotNull
    @Override
    public List getValidators(@NotNull String workspaceName, @NotNull Set principals, @NotNull MoveTracker moveTracker) {
    	return super.getValidators(workspaceName, principals, moveTracker);
    }

    @NotNull
    @Override
    public List getProtectedItemImporters() {
    	return super.getProtectedItemImporters();
    }

    //-----------------------------------------< AccessControlConfiguration >---
    @NotNull
    @Override
    public AccessControlManager getAccessControlManager(@NotNull Root root, @NotNull NamePathMapper namePathMapper) { 
    	return new CugAccessControlManager(root, namePathMapper, getSecurityProvider());
    } 

    @NotNull
    @Override
    public RestrictionProvider getRestrictionProvider() {
    	return RestrictionProvider.EMPTY;
    }

    @NotNull
    @Override
    public PermissionProvider getPermissionProvider(@NotNull Root root, @NotNull String workspaceName,
                                                    @NotNull Set principals) {
    	if (PermissionUtil.isAdminOrSystem(principals, getParameters())) {
            return new AllPermissionProviderImpl(root, this);
        }else {
            Set<String> supportedPaths = new HashSet<>();
            supportedPaths.add("/content");
            Map<String, ProtectRule> configuredProtectRules = getRegisteredProtectRules();
            Map<String, ProtectOverrideRule> configuredProtectOverrideRules = getRegisteredProtectOverrideRules();
            return new ProtectPermissionProvider(root, workspaceName, principals, configuredProtectOverrideRules, 
            		configuredProtectRules, supportedPaths, this.getContext(), this); 
        }
    }

    //--------------------------------------------------------< ProviderCtx >---

    @NotNull
    @Override
    public MountInfoProvider getMountInfoProvider() {
        return mountInfoProvider;
    }

    //--------------------------------------------------------------------------
    @Reference(name = "mountInfoProvider", cardinality = ReferenceCardinality.MANDATORY)
    public void bindMountInfoProvider(MountInfoProvider mountInfoProvider) {
        this.mountInfoProvider = mountInfoProvider;
    }

    public void unbindMountInfoProvider(MountInfoProvider mountInfoProvider) {
        this.mountInfoProvider = null;
    }
}
