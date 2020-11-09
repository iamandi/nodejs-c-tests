cmd_Release/greet.node := ln -f "Release/obj.target/greet.node" "Release/greet.node" 2>/dev/null || (rm -rf "Release/greet.node" && cp -af "Release/obj.target/greet.node" "Release/greet.node")
