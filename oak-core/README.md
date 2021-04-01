# oak-core and AEM 6.5.8 Adobe Protect
## Description
Jackrabbit-Oak is being forked for customization to oak-core. 
Tag jackrabbit-oak-1.22.6 is the source tag and baseline of the customization, as 1.22.6 is the current oak-core bundle version in AEM 6.5 with Service Pack 8. 
For upgrades to oak-core in later AEM releases, please refer to commit diffs on custom files that must be migrated/updated/refactored to the corresponding oak-core release.
Documentation may be reffered to here https://jackrabbit.apache.org/oak/docs/security/introduction.html on this oak-core forks customization of authorization and permission provider impelementation.The custom permission provider is aggregated, not a replacement, for oak-core functionality.   


## Build 
You will need to clone the project from the jackrabbit-oak level and build once so dependencies are in your .m2. for modifications to adobe protects oak-core you can build from the oak-core module level. 
To build, use the below as custom tests have not been created to satisfy jacoco code coverage
	mvn clean install -DskipTests=true -Djacoco.skip=true'