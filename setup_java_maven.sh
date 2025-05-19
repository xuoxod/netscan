#!/bin/bash
# filepath: /home/emhcet/private/projects/desktop/java/netscan/setup_java_maven.sh

set -e

# Colors for output
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
RED='\033[1;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "==============================================="
echo "   NetScan Java Frontend Maven Setup Utility   "
echo "==============================================="
echo -e "${NC}"

JAVA_FRONTEND_DIR="java_frontend"
SRC_MAIN="$JAVA_FRONTEND_DIR/src/main/java/com/emhcet/netscan"
SRC_TEST="$JAVA_FRONTEND_DIR/src/test/java/com/emhcet/netscan"
POM="$JAVA_FRONTEND_DIR/pom.xml"
APP_JAVA="$SRC_MAIN/App.java"

# Latest versions
PICOLCI_VERSION="4.7.7"
JUNIT_VERSION="5.10.2"
SUREFIRE_VERSION="3.2.5"
JAR_VERSION="3.3.0"
SHADE_VERSION="3.5.1"

# 1. Bootstrap if not present
if [ ! -d "$JAVA_FRONTEND_DIR" ]; then
    echo -e "${YELLOW}java_frontend not found. Bootstrapping a new Maven project...${NC}"
    mvn archetype:generate -DgroupId=com.emhcet.netscan -DartifactId=java_frontend -DarchetypeArtifactId=maven-archetype-quickstart -DinteractiveMode=false
    echo -e "${GREEN}Maven project created.${NC}"
    # Remove default App.java and test
    rm -f "$JAVA_FRONTEND_DIR/src/main/java/com/emhcet/netscan/App.java"
    rm -rf "$JAVA_FRONTEND_DIR/src/test/java/com/emhcet/netscan/AppTest.java"
fi

# 2. Ensure directory structure
echo -e "${CYAN}Ensuring Maven directory structure...${NC}"
mkdir -p "$SRC_MAIN"
mkdir -p "$SRC_TEST"

# 3. Ensure App.java exists
if [ ! -f "$APP_JAVA" ]; then
    echo -e "${YELLOW}App.java not found. Creating a minimal App.java...${NC}"
    cat > "$APP_JAVA" <<EOF
package com.emhcet.netscan;

import picocli.CommandLine;
import picocli.CommandLine.*;
import java.io.File;
import java.util.concurrent.Callable;

@Command(name = "MetaSuggest", version = "MetaSuggest 0.1.0", mixinStandardHelpOptions = true)
public class App implements Callable<Integer> {
    public static void main(String[] args) {
        int exitCode = new CommandLine(new App()).execute(args);
        System.exit(exitCode);
    }
    @Override
    public Integer call() throws Exception {
        System.out.println("MetaSuggest Java CLI is ready!");
        return 0;
    }
}
EOF
    echo -e "${GREEN}Created minimal App.java.${NC}"
fi

# 4. Backup pom.xml
if [ -f "$POM" ]; then
    cp "$POM" "$POM.bak.$(date +%s)"
    echo -e "${YELLOW}Backed up existing pom.xml.${NC}"
fi

# 5. Write/repair pom.xml (always writes a robust, up-to-date version)
cat > "$POM" <<EOF
<project xmlns="http://maven.apache.org/POM/4.0.0"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.emhcet</groupId>
    <artifactId>netscan-java-frontend</artifactId>
    <version>0.1.0</version>
    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <junit.jupiter.version>${JUNIT_VERSION}</junit.jupiter.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>info.picocli</groupId>
            <artifactId>picocli</artifactId>
            <version>${PICOLCI_VERSION}</version>
        </dependency>
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>\${junit.jupiter.version}</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>${SUREFIRE_VERSION}</version>
                <configuration>
                    <useModulePath>false</useModulePath>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-jar-plugin</artifactId>
                <version>${JAR_VERSION}</version>
                <configuration>
                    <archive>
                        <manifest>
                            <mainClass>com.emhcet.netscan.App</mainClass>
                        </manifest>
                    </archive>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-shade-plugin</artifactId>
                <version>${SHADE_VERSION}</version>
                <executions>
                    <execution>
                        <phase>package</phase>
                        <goals>
                            <goal>shade</goal>
                        </goals>
                        <configuration>
                            <transformers>
                                <transformer implementation="org.apache.maven.plugins.shade.resource.ManifestResourceTransformer">
                                    <mainClass>com.emhcet.netscan.App</mainClass>
                                </transformer>
                            </transformers>
                        </configuration>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
EOF

echo -e "${GREEN}pom.xml is up to date with latest dependencies and plugins.${NC}"

# 6. Final instructions
echo -e "${CYAN}"
echo "==============================================="
echo "  🎉 Setup complete! To build and run:"
echo "-----------------------------------------------"
echo "  cd $JAVA_FRONTEND_DIR"
echo "  mvn clean package"
echo "  java -jar target/netscan-java-frontend-0.1.0-shaded.jar --help"
echo "==============================================="
echo -e "${NC}"