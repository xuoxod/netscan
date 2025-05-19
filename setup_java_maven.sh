#!/bin/bash
# filepath: /home/emhcet/private/projects/desktop/java/netscan/setup_java_maven.sh

set -e

# Move to project root if not already there
cd "$(dirname "$0")"

# Define paths
JAVA_FRONTEND_DIR="java_frontend"
SRC_DIR="$JAVA_FRONTEND_DIR/src"
MAIN_JAVA_DIR="$SRC_DIR/main/java/com/emhcet/netscan"
TEST_JAVA_DIR="$SRC_DIR/test/java/com/emhcet/netscan"
APP_JAVA_PATH="$MAIN_JAVA_DIR/App.java"

# Remove old src if it exists (optional, comment out if you want to keep old files)
if [ -d "$SRC_DIR" ]; then
    echo "Removing old src directory..."
    rm -rf "$SRC_DIR"
fi

# Create Maven directory structure
echo "Creating Maven directory structure..."
mkdir -p "$MAIN_JAVA_DIR"
mkdir -p "$TEST_JAVA_DIR"

# Move existing App.java if it exists
if [ -f "$JAVA_FRONTEND_DIR/App.java" ]; then
    echo "Moving existing App.java to Maven structure..."
    mv "$JAVA_FRONTEND_DIR/App.java" "$APP_JAVA_PATH"
else
    # Create a placeholder App.java if not present
    cat > "$APP_JAVA_PATH" <<EOF
package com.emhcet.netscan;

public class App {
    public static void main(String[] args) {
        System.out.println("MetaSuggest Java CLI (Maven scaffolded)");
    }
}
EOF
fi

# Create a minimal pom.xml with Picocli dependency
cat > "$JAVA_FRONTEND_DIR/pom.xml" <<EOF
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
    </properties>
    <dependencies>
        <dependency>
            <groupId>info.picocli</groupId>
            <artifactId>picocli</artifactId>
            <version>4.7.5</version>
        </dependency>
    </dependencies>
</project>
EOF

echo "Maven Java frontend scaffold complete!"
echo "To build: cd $JAVA_FRONTEND_DIR && mvn compile"