<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
	<specVersion>
		<major>1</major>
		<minor>0</minor>
	</specVersion>
	<URLBase>http://@IPADDR#:@UPNP_PORT#</URLBase>
	<device>
	<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
	<friendlyName>Belkin @HW_ID# Router</friendlyName>
	<manufacturer>BELKIN</manufacturer>
	<manufacturerURL>http://www.belkin.com</manufacturerURL>
	<modelDescription>Belkin @HW_ID# Gateway</modelDescription>
	<modelName>Wireless-N Home Gateway</modelName>
	<modelNumber>@HW_ID#</modelNumber>
	<modelURL>http://www.belkin.com</modelURL>
	<serialNumber>123456789</serialNumber>
	<UDN>uuid:@UUID_IGD#</UDN>
	<UPC>@HW_ID#</UPC>
		<serviceList>
			<service>
				<serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
				<serviceId>urn:upnp-org:serviceId:L3Forwarding1</serviceId>
				<controlURL>/upnp/control/L3Forwarding1</controlURL>
				<eventSubURL>/upnp/event/L3Forwarding1</eventSubURL>
				<SCPDURL>/l3frwd.xml</SCPDURL>
			</service>
		</serviceList>
		<deviceList>
			<device>
				<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
				<friendlyName>WANDevice</friendlyName>
				<manufacturer>Belkin</manufacturer>
				<manufacturerURL>http://www.belkin.com/</manufacturerURL>
				<modelDescription>Residential Gateway</modelDescription>
				<modelName>Internet Connection Sharing</modelName>
				<modelNumber>1</modelNumber>
				<modelURL>http://www.belkin.com/</modelURL>
				<serialNumber>0000001</serialNumber>
				<UDN>uuid:@UUID_WAND#</UDN>
				<UPC>@HW_ID#</UPC>
				<serviceList>
					<service>
						<serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
						<serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>
						<controlURL>/upnp/control/WANCommonIFC1</controlURL>
						<eventSubURL>/upnp/event/WANCommonIFC1</eventSubURL>
						<SCPDURL>/cmnicfg.xml</SCPDURL>
					</service>
				</serviceList>
				<deviceList>
					<device>
						<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
						<friendlyName>WANConnectionDevice</friendlyName>
						<manufacturer>BELKIN</manufacturer>
						<manufacturerURL>http://www.belkin.com/</manufacturerURL>
						<modelDescription>Residential Gateway</modelDescription>
						<modelName>Internet Connection Sharing</modelName>
						<modelNumber>1</modelNumber>
						<modelURL>http://www.belkin.com/</modelURL>
						<serialNumber>0000001</serialNumber>
						<UDN>uuid:@UUID_WANCD#</UDN>
						<UPC>@HW_ID#</UPC>
						<serviceList>
							<service>
								<serviceType>urn:schemas-upnp-org:service:WANEthernetLinkConfig:1</serviceType>
								<serviceId>urn:upnp-org:serviceId:WANEthLinkC1</serviceId>
								<controlURL>/upnp/control/WANEthLinkC1</controlURL>
								<eventSubURL>/upnp/event/WANEthLinkC1</eventSubURL>
								<SCPDURL>/wanelcfg.xml</SCPDURL>
							</service>
							<service>
								<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
								<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
								<controlURL>/upnp/control/WANIPConn1</controlURL>
								<eventSubURL>/upnp/event/WANIPConn1</eventSubURL>
								<SCPDURL>/ipcfg.xml</SCPDURL>
							</service>
						</serviceList>
					</device>
				</deviceList>
			</device>
			<device>
				<deviceType>urn:schemas-upnp-org:device:LANDevice:1</deviceType>
				<friendlyName>LANDevice</friendlyName>
				<manufacturer>BELKIN</manufacturer>
				<manufacturerURL>http://www.blekin.com/</manufacturerURL>
				<modelDescription>Residential Gateway</modelDescription>
				<modelName>Residential Gateway</modelName>
				<modelNumber>1</modelNumber>
				<modelURL>http://www.belkin.com/</modelURL>
				<serialNumber>0000001</serialNumber>
				<UDN>uuid:@UUID_LAND#</UDN>
				<UPC>@HW_ID#</UPC>
				<serviceList>
					<service>
						<serviceType>urn:schemas-upnp-org:service:LANHostConfigManagement:1</serviceType>
						<serviceId>urn:upnp-org:serviceId:LANHostCfg1</serviceId>
						<controlURL>/upnp/control/LANHostCfg1</controlURL>
						<eventSubURL>/upnp/event/LANHostCfg1</eventSubURL>
						<SCPDURL>/lanhostc.xml</SCPDURL>
					</service>
				</serviceList>
			</device>
		</deviceList>
<presentationURL>http://@IPADDR#/index.html</presentationURL>
	</device>
</root>
