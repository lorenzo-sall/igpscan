# IGPscan

IGPscan is a portable tool to leverage Dynamic Routing Protocols for reconnaissance. The proposition is to address issues encountered in the current tools employed by network security experts and penetration testers to assess the security of systems running the OSPF or the EIGRP protocols.

## Interior Gateway Protocols, OSPF and EIGRP

Interior gateway protocols (IGP) are a type of routing protocol used to exchange and propagate routing information between routers. The routers participating in this process are part of the same autonomous system and update the information contained in their routing tables dynamically. OSPFv2, defined in RFC 2328 and EIGRP, released in RFC 7868 are two widely adopted interior gateway protocols.

OSPF and EIGRP are extremely important protocols for the operations of enterprise and service providers’ networks, but their complexity and the lack of security-oriented default configurations increase the attack surface and can introduce vulnerabilities in a network. For instance, interfaces that are not properly configured could send routing protocol packets out of interfaces that are not connected to gateways participating in the process, thus leaking information that can be collected and abused.

## Limitations of Current Tools

Two tools that were specifically designed to test routing protocols are Loki and Yersinia. However, these tools have not been recently updated and this makes it difficult to maintain dependencies and requirements, with a great impact on their viability.
To address the issue of aging software, the researchers Szymon Ziolkowski and Tyron Kemp developed and released the Routopsy toolkit in 2020. This powerful suite makes extensive use of containerisation, mainly relying on virtual routers and thus simplifying the development of the toolkit avoiding the need of implementing the protocols from scratch. This approach has many advantages, but comes with a cost. Routopsy requires Docker to run the virtual router, and the router image must be downloaded or somehow transferred on the machine that will run the software. This increases the cost in terms of disk space and network traffic, potentially in the order of hundreds of megabytes. This increases the risk of detection by intrusion detection systems.

The same argument is valid for the widely employed network protocol analyser Wireshark: it is not software that is commonly found installed on hosts and the executable can require up to 100 MB of disk space.

## Proposed Solution

IGPscan is intended as an addition to the already rich toolkit available to penetrarion testers. It aims to be a lightweight, extensible and portable tool, reducing the need for external modules or libraries at a minimum.