$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

########################################################
#                    MAIN FUNCTION
########################################################

function Invoke-NetworkAnalysis{
    [CmdletBinding()] Param(
    	[parameter(Mandatory = $true, Position = 0)]
    	[string[]]
        $Hosts,
    	[int32]
        $TimeOut = 1,
		$T = 10
    )

    Begin {
		$sniffer_scriptblock =
		{
				param ($IP,$RunTime, $analyzer, $Start, $TimeOut)
				$byte_in = New-Object System.Byte[] 4
				$byte_out = New-Object System.Byte[] 4 
				$byte_data = New-Object System.Byte[] 4096 
				$byte_in[0] = 1
				$byte_in[1-3] = 0 
				$byte_out[0] = 1 
				$byte_out[1-3] = 0
				$analyzer.sniffer_socket = New-Object System.Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::IP)
				$analyzer.sniffer_socket.SetSocketOption("IP","HeaderIncluded",$true) 
				$analyzer.sniffer_socket.ReceiveBufferSize = 1024
				$end_point = New-Object System.Net.IPEndpoint([System.Net.IPAddress]"$IP",0)
				$analyzer.sniffer_socket.Bind($end_point)
				$analyzer.sniffer_socket.IOControl([System.Net.Sockets.IOControlCode]::ReceiveAll,$byte_in,$byte_out)
				Write-Host("Listening IP Address = $IP")	> $null
				while($analyzer.running)
				{
					$End = Get-Date
					$time_running = $End - $Start
					if($($($time_running.Days)*24*60 + $($time_running.Hours)*60 + $($time_running.Minutes)) -gt ($TimeOut - 1)){
						return
					}
				# Inveigh sniffer is only configured to parse IPv4 Packets
					$packet_data = $analyzer.sniffer_socket.Receive($byte_data,0,$byte_data.Length,[System.Net.Sockets.SocketFlags]::None)
					$memory_stream = New-Object System.IO.MemoryStream($byte_data,0,$packet_data) 
					$binary_reader = New-Object System.IO.BinaryReader($memory_stream) 
					$version_more = $binary_reader.ReadByte()
					$IP_version = [Int]"0x$(('{0:X}' -f $version_more)[0])"
					if ($IP_version -eq 4)
					{
		# Process the IPv4 Header
						$header_length = [Int]"0x$(('{0:X}' -f $version_more)[1])" * 4
						$type_of_service= $binary_reader.ReadByte()
						$type_of_service= $binary_reader.ReadByte()
						$type_of_service= $binary_reader.ReadByte()
						# $type_of_service= $binary_reader.ReadByte()
						# Write-Host "type_of_service $type_of_service"
						$total_length = DataToUInt16 $binary_reader. ReadBytes(2) 
						$identification = $binary_reader.ReadBytes(2) 
						$flags_offset = $binary_reader.ReadBytes(2)
						$TTL = $binary_reader.ReadByte() 
						# Write-Host "TTL $TTL"
						$protocol_number = $binary_reader.ReadByte() 
						$header_checksum = [System.Net.IPAddress]::NetworkToHostOrder($binary_reader.ReadInt16()) 
						$source_IP_bytes = $binary_reader.ReadBytes(4)
						$source_IP = [System.Net.IPAddress]$source_IP_bytes 
						# Write-Host "source_IP $source_IP"
						$destination_IP_bytes = $binary_reader.ReadBytes(4) 
						$destination_IP = [System.Net.IPAddress]$destination_IP_bytes
						# Write-Host "destination_IP $destination_IP"
					}
					elseif ($IP_version -eq 6)
					{
		#	Process the IPv6 Header
		#	Intially, we won't process traffic class and flow label
		#	since they aren't needed for analysis
						$traffic_high = 0 # Get low order nibble from $version_more 
						$traffic_flow = $binary_reader.ReadBytes(3)
						$traffic_low = 0 # Get high order nibble from $traffic_flow 
						$flow_label = 0 # Zero out 4 high order bits from $traffic_flow 
						$total_length = DataToUInt16 $binary_reader.ReadBytes(2)
						#	This is next header but we may not need to do anything with this
						#	depending on whether additional headers are typically seen in the
						#	protocols we are interested in. May be useful to report this value
						#	for debugging purposes. If the protocols of interest have several
						#	extension headers, it may be useful to have a function dedicated to
						#	IPv6 next header chain walking to deteremine if one of the interesting
						#	protocols is present. Will test with IPv6.
						$protocol_number = $binary_reader.ReadByte() 
						$TTL = $binary_Reader.ReadByte() 
						$source_IP_bytes = $binary_reader.ReadBytes(16)
						$source_IP = [System.Net.IPAddress]$source_IP_bytes 
						$destination_IP_bytes = $binary_reader.ReadBytes(16) 
						$destination_IP = [System.Net.IPAddress]$destination_IP_bytes
					}
					else
					{
						continue
					}
		#	Packet processing starts here. The flow consists of inspecting the embedded protocol number first
		#	OSPF and VRRP do not use standard protocol numbers (TCP and UDP). Then we will inspect the specific protocol further
					# Write-Host("Protocol $protocol_number") > NULL
					switch ($protocol_number)
					{
		# TCP Processing 
						6
						{
							$source_port = DataToUInt16 $binary_reader.ReadBytes(2) 
							# Write-Host "source_port $source_port"
							$destination_port = DataToUInt16 $binary_reader.ReadBytes(2) 
							# Write-Host "destination_port $destination_port"
							$sequence_number = DataToUInt32 $binary_reader.ReadBytes(4) 
							$ack_number = DataToUInt32 $binary_reader.ReadBytes(12) 
							$TCP_header_length = [Int]"0x$(('{0:X}' -f $binary_reader.ReadByte())[0])" * 4
							$TCP_flags = $binary_reader.ReadByte()
							$TCP_window = DataToUInt16 $binary_reader.ReadBytes(2) 
							$TCP_checksum = [System.Net.IPAddress]::NetworkToHostOrder($binary_reader.ReadInt16()) 
							$TCP_urgent_pointer = DataToUInt16 $binary_reader.ReadBytes(2) 
							$payload_bytes = $binary_reader.ReadBytes($total_length - ($header_length + $TCP_header_length))
						}

		# UDP Processing 
						17
						{
							$source_port = $binary_reader.ReadBytes(2) 
							# Write-Host "source_port $source_port"
							$endpoint_source_port = DataToUInt16 ($source_port) 
							# Write-Host "source_port $endpoint_source_port"
							$destination_port = DataToUInt16 $binary_reader.ReadBytes(2) 
							$UDP_length = $binary_reader.ReadBytes(2)
							$UDP_length_uint = DataToUInt16 ($UDP_length) 
							$binary_reader.ReadBytes(2)
							# Write-Host "destination_port $destination_port"
							switch ($destination_port)
							{
						# DHCP Packet/Options Inspection 
								68
								{
									if ($analyzer.show_dhcp)
									{
										$dhcp_opcode = $binary_reader.ReadByte()
						#	We are only interested in DHCP Responses which may contain
						#	a boot file location which we may be able to use for boot
						#	image analysis or malicious boot attack
										if ($dhcp_opcode -eq 2)
										{
											Write-Host("DHCP response received from "	+ $source_IP.ToString()) > $null
						#	Parse the remainder of the packet
											$dhcp_hwtype = $binary_reader.ReadByte() 
											$dhcp_hwaddlength = $binary_reader.ReadByte() 
											$dhcp_hopcount = $binary_reader.ReadByte()
											$dhcp_trans_id_bytes = $binary_reader.ReadBytes(4) 
											$dhcp_trans_id = DataToUInt32 $dhcp_trans_id_bytes 
											$dhcp_lease_duration = DataToUInt16 $binary_reader.ReadBytes(2)
											$dhcp_flags = DataToUInt16 $binary_reader.ReadBytes(2) 
											$dhcp_client_ip_bytes = $binary_Reader.ReadBytes(4) 
											$dhcp_sender_ip_bytes = $binary_reader.ReadBytes(4) 
											$dhcp_server_ip_bytes = $binary_reader.ReadBytes(4) 
											$dhcp_server_ip = [System.Net.IPAddress] $dhcp_server_ip_bytes
											$dhcp_gateway_ip_bytes = $binary_reader.ReadBytes(4) 
											$dhcp_client_hw_addr_bytes = $binary_reader.ReadBytes(6) 
											$dhcp_client_hw_addr_padding = $binary_reader.ReadBytes(10)
											$dhcp_server_hostname_bytes = $binary_reader.ReadBytes(64)
											$dhcp_server_hostname_bytes = DataToString $dhcp_server_hostname_bytes
											$dhcp_server_boot_filename_bytes = $binary_reader.ReadBytes(128)
											$dhcp_server_boot_filename = DataToString $dhcp_server_boot_filename_bytes
											if ($dhcp_server_ip.Trim() -ne "")
											{
												Write-Host(" [i] DHCP Server IP: " + $dhcp_server_ip) > $null

											}
											if ($dhcp_server_hostname.Trim() -ne "")
											{
												Write-Host(" [i] DHCP Server Name: " + $dhcp_server_hostname) > $null
											}
											if ($dhcp_server_boot_filename.Trim() -ne "")
											{
												Write-Host(" [!] Boot File: " + $dhcp_server_boot_filename) > $null
												Write-Host(" [!] This File Could Contain Credentials") > $null
											}
											$dhcp_cookie_bytes = $binary_reader.ReadBytes(4)
											# Process DHCP Options
											$dhcp_option = $binary_reader.ReadByte()
											# DHCP Option 255 signifies "End Of Options" 
											while ($dhcp_option -ne 255)
											{
											# Process padding bytes
												switch ($dhcp_option)
												{
											# Handle Padding 
													0
													{
														$dhcp_option = $binary_reader.ReadByte() 
														continue
													}
											# Handle Standard PXE/Network Boot 
													66
													{
														$dhcp_option_length = $binary_reader.ReadByte()
														$dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length)
														$tftp_server_name = DataToString $dhcp_option_bytes
														Write-Host(" [!] TFTP Server Name: " + $tftp_server_name) > $null
													}
													67
													{
														$dhcp_option_length = $binary_reader.ReadByte()
														$dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length )
														$tftp_boot_filename = DataToString $dhcp_option_bytes
														Write-Host(" [!] TFTP Boot Filename: " + $tftp_boot_filename) > $null
														Write-Host(" [!] This File Could Contain Credentials") > $null
													}
													128
													{
														$dhcp_option_length = $binary_reader.ReadByte()
														$dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length)
														$tftp_server_ip = [System.Net.IPAddress]$dhcp_option_bytes
														Write-Host(" [!] TFTP Server IP: " + $tftp_server_ip) > $null
													}
													150
													{
														$dhcp_option_length = $binary_reader.ReadByte()
														$dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length)
														$tftp_server_ip = [System.Net.IPAddress]$dhcp_option_bytes
														Write-Host(" [!] TFTP Server IP: " + $tftp_server_ip) > $null
													}
											# Handle PXELINUX Requests 
													208
													{
														$dhcp_option_length = $binary_reader.ReadByte()
														$dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length)
														Write-Host(" [!] PXELINUX Magic Option Observed") > $null
													}
													209
													{
														$dhcp_option_length = $binary_reader.ReadByte()
														$dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length)
														$pxelinux_config = DataToString $dhcp_option_bytes
														Write-Host(" [!] PXELINUX Config: " + $pxelinux_config) > $null
														Write-Host(" [!] This File Should Be Inspected") > $null
													}	
													210	
													{	
														$dhcp_option_length = $binary_reader.ReadByte()
														$dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length)
														$pxelinux_path_prefix = DataToString $dhcp_option_bytes
														Write-Host( " [!] PXELINUX Prefix: " + $pxelinux_path_prefix) > $null
													}

											# Handle All Others 
													default
													{
														$dhcp_option_length = $binary_reader.ReadByte()
														$dhcp_option_bytes = $binary_reader.ReadBytes($dhcp_option_length)
														Write-Host(" [i] Observed DHCP Option: " + $dhcp_option.ToString()) > $null
														$dhcp_option = $binary_reader.ReadByte() 
														continue
													}
												}
											}
										}
									}
								}

						# NBNS Packet Inspection 
								137
								{
									if ($analyzer.show_nbns)
									{
										Write-Host("NBNS packet received from " + $source_IP.ToString()) > $null
										$nbns_queryid = DataToUInt16 $binary_reader.ReadBytes(2) 
										$nbns_control = $binary_reader.ReadByte()
						# split the control field so we can tell if this is query or response
										$nbns_control_high = [Int]"0x$(('{0:X}' -f $nbns_version_type)[0])"
										$nbns_control_low = [Int]"0x$(('{0:X}' -f $nbns_version_type)[1])"
										$nbns_rcode = $binary_reader.ReadByte()
										$nbns_qdcount = DataToUInt16 $binary_reader.ReadBytes(2)
										$nbns_ancount = DataToUInt16 $binary_reader.ReadBytes(2)
										$nbns_nscount = DataToUInt16 $binary_reader.ReadBytes(2)
										$nbns_arcount = DataToUInt16 $binary_reader.ReadBytes(2)
										if ($nbns_control_high -lt 8)
										{
											Write-Host(" [!] Potential for NBNS Poisoning Attack") > $null
											Write-Host(" [i] Type: Query") > $null 
											Write-Host(" [i] Query Count: " + $nbns_qdcount.ToString()) > $null
											for ($i = 1; $i -le $nbns_qdcount; $i++)
											{
												$nbns_field_length = $binary_reader.ReadByte() 
												$nbns_name = ""
												while ($nbns_field_length -ne 0)
												{
													$nbns_field_value_bytes = $binary_reader.ReadBytes($nbns_field_length - 2)
													$nbns_query_suffix = [System.BitConverter]::ToString($binary_reader.ReadBytes(2))
						# Used NBNS Name decoding code from Inveigh.ps1 below
													$nbns_query = [System.BitConverter]::ToString($nbns_field_value_bytes)
													$nbns_query = $nbns_query -replace "-00","" 
													$nbns_query = $nbns_query.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
													$nbns_query_string_encoded = New-Object System.String ($nbns_query,0,$nbns_query.Length)
													$nbns_query_string_encoded = $nbns_query_string_encoded.Substring(0,$nbns_query_string_encoded.IndexOf("CA"))
													$nbns_query_string_subtracted = "" 
													$nbns_query_string = ""
													$n = 0
													do
													{
														$nbns_query_string_sub = (([Byte][Char]($nbns_query_string_encoded.Substring($n,1))) - 65)
														$nbns_query_string_subtracted += ([System.Convert]::ToString($nbns_query_string_sub,16))
														$n += 1
													}
													until($n -gt ($nbns_query_string_encoded.Length - 1))
													$n = 0

													do
													{
														$nbns_query_string += ([Char]([System.Convert]::ToInt16($nbns_query_string_subtracted.Substring($n,2),16)))
														$n += 2
													}
													until($n -gt ($nbns_query_string_subtracted.Length - 1) -or $nbns_query_string.Length -eq 15)
							# Name Conversion is complete
													$nbns_name = $nbns_name + $nbns_query_string
							# Read Next Length for Loop Execution, for NBNS there should only be one record
													$nbns_field_length = $binary_reader.ReadByte()
													if ($nbns_field_length -ne 0)
													{
														$nbns_name = ($nbns_name + ".")
													}
													switch ($nbns_query_suffix)
													{
														'41-41'
														{
															$nbns_service = "Workstation/Redirector"
														}
														'41-44'
														{
															$nbns_service = "Messenger"
														}
														'43-47'
														{
															$nbns_service = "Remote Access"
														}
														'43-41'
														{
															$nbns_service = "Server"
														}
														'43-42'
														{
															$nbns_service = "Remote Access Client"
														}
														'42-4C'
														{
															$nbns_service = "Domain Master Browser"
														}
														'42-4D'
														{
															$nbns_service = "Domain Controllers"
														}
														'42-4E'
														{
															$nbns_service = "Master Browser"
														}
														'42-4F'
														{
															$nbns_service = "Browser Election"
														}
													}
												}
												$nbns_record_type = DataToUInt16 $binary_reader.ReadBytes(2)
												$nbns_record_class = DataToUInt16 $binary_reader.ReadBytes(2)
												Write-Host(" [i] Host: " + $nbns_name) > $null
												Write-Host(" [i] Service Type: " + $nbns_service) > $null
											}
										}
										else
										{
											Write-Host(" [i] Type: Response") > $null
											Write-Host(" [i] Response Count: " + $nbns_ancount.ToString()) > $null
							# May Parse NBNS Responses Further In The Future
										}
									}
								}
							# HSRP Packet Inspection 
								1985
								{
									if ($analyzer.show_hsrp)
									{
							# This is for HSRP v0/1. HSRP v2 uses multicast IP
										224.0.0.102
							# HSRP destination should be 224.0.0.2
										if ($destination_IP.ToString() -eq "224.0.0.2")
										{
											$hsrp_version = $binary_reader.ReadByte() 
											$hsrp_opcode = $binary_reader.ReadByte() 
											$hsrp_state = $binary_reader.ReadByte() 
											$hsrp_hellotime = $binary_reader.ReadByte() 
											$hsrp_holdtime = $binary_reader.ReadByte() 
											$hsrp_priority = $binary_reader.ReadByte() 
											$hsrp_group = $binary_reader.ReadByte() 
											$hsrp_reserved = $binary_reader.ReadByte()
											$hsrp_auth_bytes = $binary_reader.ReadBytes(8) 
											$hsrp_auth = DataToString 0 8 $hsrp_auth_bytes 
											$hsrp_groupip_bytes = $binary_reader.ReadBytes(4) 
											$hsrp_groupip = [System.Net.IPAddress] $hsrp_groupip_bytes
											Write-Host("HSRP v" + $hsrp_version.ToString() + " Packet Observed from " + $source_IP.ToString()) > $null
											switch ($hsrp_opcode)
											{
												0
												{
													Write-Host(" [i] Operation: Hello" ) > $null
													Write-Host(" [i] Hello Time: " + $hsrp_hellotime.ToString() + " seconds") > $null
													Write-Host(" [i] Hold Time: " + $hsrp_holdtime.ToString() + " seconds") > $null
												}
												1
												{
													Write-Host(" [i] Operation: Coup") > $null
												}
												2
												{
													Write-Host(" [i] Operation: Resign") > $null
												}
											}
											switch ($hsrp_state)
											{
												0
												{
													Write-Host(" [i] State: Initial") > $null
												}
												1
												{
													Write-Host(" [i] State: Learn") > $null
												}
												2
												{
													Write-Host(" [i] State: Listen") > $null
												}
												4
												{
													Write-Host(" [i] State: Speak") > $null
												}
												8
												{
													Write-Host(" [i] State: Standby") > $null
												}
												16
												{
													Write-Host(" [i] State: Active") > $null
												}
											}
											Write-Host(" [i] Priority: " + $hsrp_priority.ToString()) > $null
											if ($hsrp_priority -lt 250)
											{
												Write-Host(" [!] Priority May Be Low. Potential for Hijacking")
											}
											Write-Host(" [i] Group: " + $hsrp_group.ToString()) > $null
											Write-Host(" [!] Password: " + $hsrp_auth) > $null
											Write-Host(" [i] Group IP: " + $hsrp_groupip.ToString()) > $null
										}
										else
										{
											Write-Host("Packet received on HSRP UDP Port with wrong destination address") > $null
										}
									}
								}
							# mDNS Packet Inspection 
								5353
								{
									if ($analyzer.show_mdns)
									{
							# Need to gather full payload up front because of DNS compression
										$payload_bytes = $binary_reader.ReadBytes(($UDP_length_uint - 2) * 4)

							# mDNS destination should be 224.0.0.251
										if ($destination_IP.ToString() -eq "224.0.0.251")
										{
											Write-Host("mDNS Packet Observed from " + $source_IP.ToString()) > $null
											$mdns_queryid = DataToUInt16 $payload_bytes[0..1] $mdns_control = $payload_bytes[2]
							# split the control field so we can tell if this is query or response
											$mdns_control_high = [Int]"0x$(('{0:X}' -f $mdns_control)[0])"
											$mdns_control_low = [Int]"0x$(('{0:X}' -f $mdns_version_type)[1])"
											$mdns_rcode =	$payload_bytes[3]
											$mdns_qdcount = DataToUInt16 $payload_bytes[4..5]
											$mdns_ancount = DataToUInt16 $payload_bytes[6..7]
											$mdns_nscount =	DataToUInt16 $payload_bytes[8..9]
											$mdns_arcount =	DataToUInt16 $payload_bytes[10.11]
											if ($mdns_control_high -lt 8)
											{
												Write-Host(" [!] Potential for mDNS Cache Poisoning Attack") > $null
												Write-Host(" [i] Type: Query") > $null
												Write-Host(" [i] Count: " + $mdns_qdcount.ToString()) > $null
												$payload_index = 12
												for($i = 1; $i -le $mdns_qdcount; $i++)
												{
													$mdns_field_length = $payload_bytes[$payload_index]
													$payload_index = $payload_index + 1
													$name = ""
													while($mdns_field_length -ne 0)
													{
														$mdns_field_value_bytes = $payload_bytes[$payload_index..($payload_index + $mdns_field_length - 1)]
														$payload_index = $payload_index + $mdns_field_length 
														$mdns_field_value = DataToString 0 $mdns_field_length $mdns_field_value_bytes 
														$name = $name + $mdns_field_value
														$mdns_field_length = $payload_bytes[$payload_index]
														$payload_index = $payload_index + 1
												# When DNS Compression is in use, the record will not be terminated with a null
												# Instead, a byte value of 192 (or C0) will be found indicating that the next byte
												# represents the offset into the DNS packet where the request/response continues.
														if($mdns_field_length -eq 192)
														{
															$mdns_ptr_offset = $payload_bytes[$payload_index]
															$payload_index = $payload_index + 1
															$mdns_field_length = $payload_bytes[$mdns_ptr_offset]
															$mdns_ptr_offset = $mdns_ptr_offset + 1
															while($mdns_field_length -ne 0)
															{
																$mdns_field_value_bytes = $payload_bytes[$mdns_ptr_offset..($mdns_ptr_offset + $mdns_field_length - 1)]
																$mdns_ptr_offset = $mdns_ptr_offset + $mdns_field_length 
																$mdns_field_value = DataToString 0 $mdns_field_length $mdns_field_value_bytes 
																$name = $name + $mdns_field_value 
																$mdns_field_length = $payload_bytes[$mdns_ptr_offset]
																$mdns_ptr_offset = $mdns_ptr_offset + 1
																if($mdns_field_length -ne 0)
																{
																	$name =($name + ".")
																}  
															}
															break
														}
														if($mdns_field_length -ne 0)
														{
															$name=($name + ".")
														}
													}
													$mdns_record_type = $payload_bytes[$payload_index..($payload_index + 1)]
													$payload_index = $payload_index + 2
													$mdns_record_class = $payload_bytes[$payload_index..($payload_index + 1)]
													$payload_index = $payload_index + 2 
													Write-Host(" [i] Host: " + $name) > $null
												}
											}
											else
											{
												Write-Host(" [i] Type: Response") > $null
												Write-Host(" [i] Count: " + $mdns_ancount.ToString()) > $null
							# May Parse mDNS Responses Further In The Future
											}
										}
										else
										{
											$analyzer.console_queue. Add("Packet received on mDNS UDP Port with wrong destination address") > $null
										}
									}
								}
							# LLMNR Packet Inspection 
								5355
								{
									if ($analyzer.show_llmnr)
									{
										if ($destination_IP.ToString() -eq "224.0.0.252")
										{
											Write-Host("LLMNR Packet Observed from " + $source_IP.ToString()) > $null
											$llmnr_queryid = DataToUInt16 $payload_bytes[0..1] 
											$llmnr_control = $payload_bytes[2]
								# split the control field so we can tell if this is query or response
											$llmnr_control_high = [Int]"0x$(('{0:X}' -f $llmnr_control)[0])"
											$llmnr_control_low = [Int]"0x$(('{0:X}' -f $llmnr_version_type)[1] ) "
											$llmnr_rcode =	$payload_bytes[3]
											$llmnr_qdcount	= DataToUInt16 $payload_bytes[4..5]
											$llmnr_ancount	= DataToUInt16 $payload_bytes[6..7]
											$llmnr_nscount	=	DataToUInt16	$payload_bytes[8..9]
											$llmnr_arcount	=	DataToUInt16	$payload_bytes[10.11]
											if ($llmnr_control_high -lt 8)
											{
												Write-Host(" [!] Potential for LLMNR Cache Poisoning Attack") > $null
												Write-Host(" [i] Type: Query") > $null
												Write-Host(" [i] Count: " + $llmnr_qdcount.ToString()) > $null
												$payload_index = 12
												for ($i = 1; $i -le $llmnr_qdcount; $i++)
												{
													$llmnr_field_length = $payload_bytes[$payload_index]
													$payload_index = $payload_index + 1
													$name = ""
													while ($llmnr_field_length -ne 0)
													{
														$llmnr_field_value_bytes = $payload_bytes[$payload_index..($payload_index + $llmnr_field_length - 1)]
														$payload_index = $payload_index + $llmnr_field_length
														$llmrn_field_value = DataToString 0 $mdns_field_length $llmnr_field_value_bytes
														$name = $name + $llmnr_field_value
														$llmnr_field_length = $payload_bytes[$payload_index]
														$payload_index = $payload_index + 1
								# When DNS Compression is in use, the record will not be terminated with a null
														# Instead, a byte value of 192 (or C0) will be found indicating that the next byte
														# represents the offset into the DNS packet where the request/response continues.
														if($llmnr_field_length -eq 192)
														{
															$llmnr_ptr_offset = $payload_bytes[$payload_index]
															$payload_index = $payload_index + 1
															$llmnr_field_length = $payload_bytes[$llmnr_ptr_offset]
															$llmnr_ptr_offset = $mdns_ptr_offset + 1
															while($llmnr_field_length -ne 0)
															{
																$llmnr_field_value_bytes = $payload_bytes[$llmnr_ptr_offset..($llmnr_ptr_offset + $llmnr_field_length - 1)]
																$llmnr_ptr_offset = $llmnr_ptr_offset + $llmnr_field_length 
																$llmnr_field_value = DataToString 0 $llmnr_field_length $llmnr_field_value_bytes
																$name = $name + $llmnr_field_value
																$llmnr_field_length = $payload_bytes[$llmnr_ptr_offset]
																$llmnr_ptr_offset = $llmnr_ptr_offset + 1
																if($llmnr_field_length -ne 0)
																{ 
																	$name =($name + ".")
																}  
															}
															break
														}
														if($llmnr_field_length -ne 0)
														{
															$name = ($name + ".")
														}
													}
													$llmnr_record_type = $payload_bytes[$payload_index..($payload_index + 1)]
													$payload_index = $payload_index + 2
													$llmnr_record_class = $payload_bytes[$payload_index..($payload_index + 1)]
													$payload_index = $payload_index + 2
													Write-Host(" [i] Host: " + $name) > $null
												}
											}
											else
											{
												Write-Host(" [i] Type: Response") > $null
												Write-Host(" [i] Count: " + $llmnr_ancount.ToString()) > $null
											# May Parse LLMNR Responses Further In The Future
											}
										}
										else
										{
											Write-Host("Packet received on LLMNR UDP Port with wrong destination address") > $null
										}
									}
								}
								default
								{
									# Do Nothing
								}
							}
						}
		# OSPF Processi
						89
						{
							if ($analyzer.show_ospf)
							{
								if ($destination_IP.ToString() -eq "224.0.0.5")
								{
									$ospf_version = $binary_reader.ReadByte() 
									$ospf_type = $binary_reader.ReadByte()
									$ospf_length = DataToUInt16 $binary_reader.ReadBytes(2) 
									$ospf_router_bytes = $binary_reader.ReadBytes(4) 
									$ospf_router = [System.Net.IPAddress]$ospf_router_bytes 
									$ospf_area_bytes = $binary_reader.ReadBytes(4) 
									$ospf_area = [System.Net.IPAddress]$ospf_area_bytes 
									$ospf_checksum = DataToUInt16 $binary_reader.ReadBytes(2) 
									$ospf_authType = DataToUInt16 $binary_reader.ReadBytes(2)
									Write-Host("OSPF v" + $ospf_version.ToString() + " Packet Observed from " + $source_IP.ToString()) > $null
									switch($ospf_authType)
									{
						# Handle OSPF Packets with NULL Auth 
										0
										{
											switch($ospf_type)
											{
												1
												{
													Write-Host(" [i] Type: Hello packet.") > $null
												}
												2
												{
													Write-Host(" [i] Type: DB Descriptor packet.") > $null
												}
												3
												{
													Write-Host(" [i] Type: LS Request packet.") > $null
												}
												4
												{
													Write-Host(" [!] Type: LS Update packet.") > $null
												}
												5
												{
													Write-Host(" [i] Type: LS Ack packet.") > $null
												}
											}
											Write-Host(" [!] Auth: NULL") > $null
										}

						# Handle OSPF Packets with Password Auth 
										1
										{
											switch($ospf_type)
											{
												1
												{
													Write-Host(" [i] Type: Hello packet.") > $null
												}
												2
												{
													Write-Host(" [i] Type: DB Descriptor packet.") > $null
												}
												3
												{
													Write-Host(" [i] Type: LS Request packet.") > $null
												}
												4
												{
													Write-Host(" [!] Type: LS Update packet.") > $null
												}
												5
												{
													Write-Host(" [i] Type: LS Ack packet.") > $null
												}
											}
											Write-Host(" [!] Auth: Password") > $null
											$password_bytes = $binary_reader.ReadBytes(8) 
											$ospf_authData = DataToString 0 8 $password_bytes 
											Write-Host(" [!] Password: " + $ospf_authData) > $null
										}

						# Handle OSPF Packets With Cryptographic Auth 
										2
										{
											$null_bytes = $binary_reader.ReadBytes(2) 
											$ospf_key_id = $binary_reader.ReadByte() 
											$ospf_auth_length = $binary_reader.ReadByte()
											$ospf_auth_sequence_bytes = $binary_reader.ReadBytes(4) 
											$ospf_auth_sequence = DataToUInt32 $ospf_auth_sequence_bytes
											switch($ospf_type)
											{
												1
												{
													Write-Host(" [i] Type: Hello packet.") > $null
													Write-Host(" [i] Auth: Cryptographic (MD5)") > $null
													Write-Host(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
													Write-Host(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null
													$ospf_netmask_bytes = $binary_reader.ReadBytes(4) 
													$ospf_netmask = [System.Net.IPAddress]$ospf_netmask_bytes
													$opsf_hello_interval = DataToUInt16 $binary_reader.ReadBytes(2)
													$ospf_hello_options = $binary_reader.ReadByte() 
													$ospf_hello_router_pri = $binary_reader.ReadByte()
													$ospf_dead_interval_bytes = $binary_reader.ReadBytes(4)
													$ospf_dead_interval = DataToUInt32 $ospf_dead_interval_bytes
													$ospf_dr_bytes = $binary_reader.ReadBytes(4) 
													$ospf_dr_ip = [System.Net.IPAddress]$ospf_dr_bytes
													$ospf_br_bytes = $binary_reader.ReadBytes(4) 
													$ospf_br_ip = [System.Net.IPAddress]$ospf_br_bytes
													$ospf_crypt_hash_bytes = $binary_reader.ReadBytes(16)
													$ospf_crypt_hash = DataToHexString 0 16 $ospf_crypt_hash_bytes
													Write-Host(" [i] Auth Hash: " + $ospf_crypt_hash.ToString())
													Write-Host(" [i] Designated Router: " + $ospf_dr_ip.ToString())
												}
												2
												{
												# May need to expand on DB Descriptor Packets (Just to get routing table).
												Write-Host(" [i] Type: DB Descriptor packet.") > $null
												Write-Host(" [i] Auth: Cryptographic (MD5)") > $null
												Write-Host(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
												Write-Host(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null
												}
												3
												{
												# Link-State Request Packets are Less Interesting
													Write-Host(" [i] Type: LS Request packet.") > $null
													Write-Host(" [i] Auth: Cryptographic (MD5)") > $null
													Write-Host(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
													Write-Host(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null
												}
												4
												{
													# Link-State Update Packets Can Be Used to Build a Routing Table
													Write-Host(" [!] Type: LS Update packet.") > $null
													Write-Host(" [i] Auth: Cryptographic (MD5)") > $null
													Write-Host(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
													Write-Host(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null
												}
												5
												{
												# Link-State Acknowledgement Packets May Need to be Used to Validate Updates
													Write-Host(" [i] Type: LS Ack packet.") > $null
													Write-Host(" [i] Auth: Cryptographic (MD5)") > $null
													Write-Host(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
													Write-Host(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null
												}
											}
										}
									}
								}
								elseif ($destination_IP.ToString() -eq "224.0.0.6")
								{
									$ospf_version = $binary_reader.ReadByte() 
									$ospf_type = $binary_reader.ReadByte()
									$ospf_length = DataToUInt16 $binary_reader.ReadBytes(2) 
									$ospf_router_bytes = $binary_reader.ReadBytes(4) 
									$ospf_router = [System.Net.IPAddress]$ospf_router_bytes 
									$ospf_area_bytes = $binary_reader.ReadBytes(4) 
									$ospf_area = [System.Net.IPAddress]$ospf_area_bytes 
									$ospf_checksum = DataToUInt16 $binary_reader.ReadBytes(2) 
									$ospf_authType = DataToUInt16 $binary_reader.ReadBytes(2)

									Write-Host("OSPF v" + $ospf_version.ToString() + " Packet Observed from " + $source_IP.ToString()) > $null
									switch($ospf_authType)
									{
									# Handle OSPF Packets with NULL Auth 
										0
										{
											switch($ospf_type)
											{
												1
												{
													Write-Host(" [i] Type: Hello packet.") > $null
												}
												2
												{
													Write-Host(" [i] Type: DB Descriptor packet.") > $null
												}
												3
												{
													Write-Host(" [i] Type: LS Request packet.") > $null
												}
												4
												{
													Write-Host(" [!] Type: LS Update packet.") > $null
												}
												5
												{
													Write-Host(" [i] Type: LS Ackpacket.") > $null
												}
											}
											Write-Host(" [!] Auth: NULL") > $null
										}

						# Handle OSPF Packets with Password Auth 
										1
										{
											switch($ospf_type)
											{
												1
												{
													Write-Host(" [i] Type: Hello packet.") > $null
												}
												2
												{
													Write-Host(" [i] Type: DB Descriptor packet.") > $null
												}
												3
												{
													Write-Host(" [i] Type: LS Request packet.") > $null
												}
												4
												{
													Write-Host(" [!] Type: LS Update packet.") > $null
												}
												5
												{
													Write-Host(" [i] Type: LS Ack packet.") > null
												}
											}
											Write-Host(" [!] Auth: Password") > $null 
											$password_bytes = $binary_reader.ReadBytes(8) 
											$ospf_authData = DataToString 0 8 $password_bytes 
											Write-Host(" [!] Password: " + $ospf_authData) > $null
										}

						# Handle OSPF Packets With Cryptographic Auth 
										2
										{
											$null_bytes = $binary_reader.ReadBytes(2) 
											$ospf_key_id = $binary_reader.ReadByte() 
											$ospf_auth_length = $binary_reader.ReadByte()
											$ospf_auth_sequence_bytes = $binary_reader.ReadBytes(4) 
											$ospf_auth_sequence = DataToUInt32 $ospf_auth_sequence_bytes
											switch($ospf_type)
											{
												1
												{
													Write-Host(" [i] Type: Hello packet.") > $null
													Write-Host(" [i] Auth: Cryptographic (MD5)") > $null
													Write-Host(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
													Write-Host(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null
													$ospf_netmask_bytes = $binary_reader.ReadBytes(4) 
													$ospf_netmask = [System.Net.IPAddress]$ospf_netmask_bytes
													$opsf_hello_interval = DataToUInt16 $binary_reader.ReadBytes(2)
													$ospf_hello_options = $binary_reader.ReadByte()
													$ospf_hello_router_pri = $binary_reader.ReadByte()
													$ospf_dead_interval_bytes = $binary_reader.ReadBytes(4)
													$ospf_dead_interval = DataToUInt32 $ospf_dead_interval_bytes
													$ospf_dr_bytes = $binary_reader.ReadBytes(4)
													$ospf_dr_ip = [System.Net.IPAddress]$ospf_dr_bytes
													$ospf_br_bytes = $binary_reader.ReadBytes(4)
													$ospf_br_ip =[System.Net.IPAddress] $ospf_br_bytes
													$ospf_crypt_hash_bytes = $binary_reader.ReadBytes(16)
													$ospf_crypt_hash = DataToHexString 0 16 $ospf_crypt_hash_bytes
													Write-Host(" [i] Auth Hash: " + $ospf_crypt_hash.ToString())
													Write-Host(" [i] Designated Router: " + $ospf_dr_ip.ToString())
												}
												2
												{
												# May need to expand on DB Descriptor Packets (Just to get routing table).
													Write-Host(" [i] Type: DB Descriptor packet.") > $null
													Write-Host(" [i] Auth: Cryptographic (MD5)") > $null
													Write-Host(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
													Write-Host(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null
												}
												3
												{
												# Link-State Request Packets are Less Interesting
													Write-Host(" [i] Type: LS Request packet.") > $null
													Write-Host(" [i] Auth: Cryptographic (MD5)") > $null
													Write-Host(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
													Write-Host(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null
												}
												4
												{
												# Link-State Update Packets Can Be Used to Build a Routing Table
													Write-Host(" [!] Type: LS Update packet.") > $null
													Write-Host(" [i] Auth: Cryptographic (MD5)") > $null
													Write-Host(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
													Write-Host(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null
												}
												5
												{
												# Link-State Acknowledgement Packets May Need to be Used to Validate Updates
													Write-Host(" [i] Type: LS Ack packet.") > $null
													Write-Host(" [i] Auth: Cryptographic (MD5)") > $null
													Write-Host(" [i] KeyID: " + $ospf_key_id.ToString()) > $null
													Write-Host(" [i] Auth Seq: " + $ospf_auth_sequence.ToString()) > $null
												}
											}
										}
									}
								}
								else			
								{
									Write-Host("Packet received for OSPF Protocol ID with wrong destination address") > $null
								}
							}
						}

		# VRRP Processing 
						112
						{
							if ($analyzer.show_vrrp)
							{
								if ($destination_IP.ToString() -eq "224.0.0.18")
								{
									$vrrp_version_type = $binary_reader.ReadByte()
									$vrrp_version = [Int]"0x$(('{0:X}' -f $vrrp_version_type)[0])"
						# Only type 1 is defined in the RFC, all others are non-existent 
									$vrrp_type = [Int]"0x$(('{0:X}' -f $vrrp_version_type)[1])" 
									$vrrp_rtr_id = $binary_reader.ReadByte()
									$vrrp_priority = $binary_reader.ReadByte() 
									$vrrp_addr_count = $binary_reader.ReadByte()

									Write-Host("VRRP v" + $vrrp_version + " Packet Observed from " + $source_IP.ToString()) > $null
									Write-Host(" [i] Router ID: " + $vrrp_rtr_id.ToString())
									Write-Host(" [i] Priority: " + $vrrp_priority.ToString())
									if ($vrrp_priority -lt 250)
									{
										Write-Host(" [!] Priority May Be Low. Potential for Hijacking")
									}
									Write-Host(" [i] Addresses: " + $vrrp_addr_count.ToString())
									# VRRP v2 is IPv4 Only 
									if ($vrrp_version -lt 3)
									{
										$vrrp_auth_type = $binary_reader.ReadByte() 
										$vrrp_advert_interval = $binary_reader.ReadByte() 
										$vrrp_checksum = DataToUInt16 $binary_reader.ReadBytes(2)
									# Might be wise to validate this against packet length to handle malformed packets
										for ($i = 1; $i -le $vrrp_addr_count; $i++)
										{
											try
											{
												$vrrp_address_bytes = $binary_reader.ReadBytes(4) 
												$vrrp_address = [System.Net.IPAddress]$vrrp_address_bytes
												Write-Host(" [i] Address " + $i.ToString() + ": " + $vrrp_address.ToString()) > $null
												}
											catch
											{
												Write-Host(" [w] Malformed Packet!!")
											}
										}
										try
										{
											switch ($vrrp_auth_type)
											{
												0
												{
													Write-Host(" [!] Auth: None") > $null
												}
												1
												{
													Write-Host(" [!] Auth: Simple Text Password") > $null
													$vrrp_auth_data_bytes = $binary_reader.ReadBytes(8)
													$vrrp_auth_data = DataToString 0 8 $vrrp_auth_data_bytes
													Write-Host(" [!] Password: " + $vrrp_auth_data) > $null
												}
												2
												{
													Write-Host(" [i] Auth: IP Auth Header") > $null
												}
											}
										}
										catch
										{
										}
									}
									elseif ($IP_version -eq 4)
									{
										$vrrp_rsv_advert_interval_bytes = $binary_reader.ReadBytes(4) 
										$vrrp_rsv_advert_interval = DataToUInt32 $vrrp_rsv_advert_interval_bytes
										$vrrp_checksum = DataToUInt16 $binary_reader.ReadBytes(2)
						# Might be wise to validate this against packet length to handle malformed packets
										for ($i = 1; $ i - le $vrrp_addr_count; $i++)
										{
											try
											{
												$vrrp_address_bytes = $binary_reader.ReadBytes(4) 
												$vrrp_address = [System.Net.IPAddress]$vrrp_address_bytes
												Write-Host(" [i] Address " + $i.ToString() + ": " + $vrrp_address.ToString()) > $null
											}
											catch
											{
												Write-Host(" [w] Malformed Packet!!")
											}
										}
									}
									elseif ($IP_version -eq 6)
									{
										$vrrp_rsv_advert_interval_bytes = $binary_reader.ReadBytes(4) 
										$vrrp_rsv_advert_interval = DataToUInt32 $vrrp_rsv_advert_interval_bytes
										$vrrp_checksum = DataToUInt16 $binary_reader.ReadBytes(2)
										# Might be wise to validate this against packet length to handle malformed packets
										for ($i = 1; $i -le $vrrp_addr_count; $i++)
										{
											try
											{
												$vrrp_address_bytes = $binary_reader.ReadBytes(16) 
												$vrrp_address = [System.Net.IPAddress]$vrrp_address_bytes
												Write-Host(" [i] Address " + $i.ToString() + ": " + $vrrp_address.ToString()) > $null
											}
											catch
											{
												Write-Host(" [w] Malformed Packet!!")
											}
										}
									}
								}
								else
								{
									Write-Host("Packet received on VRRP Protocol ID with wrong destination address") > $null
								}
							}
						}
					}
				}
				$binary_reader.Close() 
				$memory_stream.Dispose() 
				$memory_stream.Close()
			}
		function DataToUInt16($field)
		{
			[Array]::Reverse($field)
			return [System.BitConverter]::ToUInt16($field,0)
		}
		function DataToUInt32($field)
		{
			[Array]::Reverse($field)
			return [System.BitConverter]::ToUInt32($field,0)
		}
		function DataLength2
		{
			param ([Int]$length_start,[Byte[]]$string_extract_data)
			$string_length = [System.BitConverter]::ToUInt16($string_extract_data[$length_start..($length_start + 1)],0)
			return $string_length
		}
		function DataLength4
		{
			param([Int]$length_start,[Byte[]]$string_extract_data)
			$string_length = [System.BitConverter]::ToUInt32($string_extract_data[$length_start..($length_start + 3)],0)
			return $string_length
		}
		function DataToString
		{
			param ([Int]$string_start,[Int]$string_length,[Byte[]]$string_extract_data)
			$string_data =[System.BitConverter]::ToString($string_extract_data[$string_start..($string_start + $string_length - 1)])
			$string_data = $string_data -replace "-00","" 
			$string_data = $string_data.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
			$string_extract = New-Object System.String ($string_data,0,$string_data.Length) 
			return $string_extract
		}
		function DataToHexString
		{
			param ([Int]$string_start,[Int]$string_length,[Byte[]]$string_extract_data)
			$string_data = [System.BitConverter]::ToString($string_extract_data[$string_start..($string_start + $string_length - 1)])
			$string_data = $string_data -replace "-",""
			$string_extract = New-Object System.String ($string_data,0,$string_data.Length) 
			return $string_extract.ToLower()
		}
	 }

    Process {
		$Start = Get-Date
		if(!$Hosts)
		{
			$Hosts = (Test-Connection 127.0.0.1 -count 1 | Select-Object -ExpandProperty Ipv4Address)
		}
		 $Computers = Invoke-InitHosts $Hosts
		if(!$analyzer)
		{
			$global:analyzer = [HashTable]::Synchronized(@{})
			$analyzer.console_queue = New-Object System.Collections.ArrayList 
			$analyzer.show_dhcp = $true
			$analyzer.show_hsrp = $true 
			$analyzer.show_llmnr = $true 
			$analyzer.show_mdns = $true 
			$analyzer.show_nbns = $true 
			$analyzer.show_ospf = $true 
			$analyzer.show_vrrp = $true
			$analyzer.rule_name = "Multicast Inbound Allow"
		}
		$analyzer.sniffer_socket = $null 
		$analyzer.running = $true

		Write-Host("Analyzer started at $(Get-Date -format 's')") > $null
		$firewall_status = netsh advfirewall show allprofiles state | Where-Object {$_ -match 'ON'}
		if($firewall_status)
		{
			Write-Host("Windows Firewall = Enabled") > $null 
			$firewall_rules = New-Object -comObject HNetCfg.FwPolicy2
			$firewall_powershell = $firewall_rules.rules | Where-Object {$_.Enabled -eq $true -and $_.Direction -eq 1} |Select-Object -Property Name | Select-String "Windows PowerShell}"
			if ($firewall_powershell)
			{
				Write-Host("Windows Firewall - PowerShell.exe = Allowed") > $null

			}
	#	The Windows firewall does not allow inbound multicast packets by default. As a result, if the firewall
	#	is enabled we won't be able to check for some of the interesting protocols. Therefore, we can either
	#	attempt to disable the firewall using
	#	netsh advfirewall set allprofiles state off < This increases our exposure to attack. We only want to see inbound traffic
	#	a better option is to allow the multicast addresses we're interested in inbound
	#	netsh advfirewall firewall add rule name="Multicast Inbound Allow" dir=in action=allow localip="224.0.0.0/24"

			Write-Host("Inserted Inbound Multicast Rule") > $null 
			netsh advfirewall firewall add rule name="Multicast Inbound Allow" dir=in action=allow localip="224.0.0.0/24"

		}
        $ScriptParams = @{
            'RunTime' = $RunTime
            'analyzer' = $analyzer
			'Start' = $Start
			'TimeOut' = $TimeOut
        }
        if ($Computers.Length -gt 0) {
            Invoke-Threaded -Computers $Computers -ScriptBlock $sniffer_scriptblock -ScriptParameters $ScriptParams -Threads $T
        }
    }

    End {
        Write-Host "Done."
    }
}

########################################################
#                       FUNCTION
########################################################


########################################################
#                     CORE FUNCTION
########################################################

function Invoke-InitHosts {
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [object[]]
        $Hosts,

        [switch]
        $NoResolve
    )

    $Computers = @()
    $NumHost = $Hosts.Count-1
    for ($i = 0; $i -le $NumHost; $i++) {
        if ($Hosts[$i] -match "^(?:[0-9]{1,3}\.){2}(?:[0-9]{1,3})$") # subnet /24
        {
            $a = $Hosts[$i].Split('.')[0]
            $b = $Hosts[$i].Split('.')[1]
            $c = $Hosts[$i].Split('.')[2]

            [int]$t = [convert]::ToInt32($d)
            for ($j = 1; $j -le 254; $j++)
            {
                $IP = "$a.$b.$c.$j"
                $Computers += $IP

            }
        }
        elseif ($Hosts[$i] -match "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$") # single IP
        {
            $IP = $Hosts[$i]
            $Computers += $IP
        }
        ElseIf ($Hosts[$i] -match "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\-[0-9]{1,3}$") # ip range
        {
            $begin = $Hosts[$i].Split('-')[0]
            $end = $Hosts[$i].Split('-')[1]

            $a = $begin.Split('.')[0]
            $b = $begin.Split('.')[1]
            $c = $begin.Split('.')[2]
            $d = $begin.Split('.')[3]

            [int]$t = [convert]::ToInt32($d)
            for ($j = $t; $j -le $end; $j++)
            {
                $IP = "$a.$b.$c.$j"
                $Computers += $IP
            }
        }
        ElseIf ($Hosts[$i] -match "^(?:[0-9]{1,3}\.){2}[0-9]{1,3}\-[0-9]{1,3}$") # multi subnet
        {
            $begin = $Hosts[$i].Split('-')[0]
            $end = $Hosts[$i].Split('-')[1]

            $a = $begin.Split('.')[0]
            $b = $begin.Split('.')[1]
            $c = $begin.Split('.')[2]

            $intC = [convert]::ToInt32($c)
            $intE = [convert]::ToInt32($end)

            for ($ot3 = $intC; $ot3 -le $intE; $ot3++)
            {
                for ($ot4 = 1; $ot4 -le 254; $ot4++)
                {
                    $IP = "$a.$b.$ot3.$ot4"
                    $Computers += $IP
                }
            }
        }
        Else { # Host Name
            Try {
                $ComputerName = Get-NameField -Object $Hosts[$i]
                #$IP = [System.Net.Dns]::GetHostAddresses($Hosts[$i])[0].IPAddressToString
                ## $IPs = [system.net.dns]::gethostaddresses($Hosts[$i])|?{$_.scopeid -eq $null}|%{$_.ipaddresstostring}
                #$Computers += $IP#s[0]

                if ($NoResolve) {
                    $Computers += $ComputerName
                }
                else {
                    # get the IP resolution of this specified hostname
                    $Results = @(([Net.Dns]::GetHostEntry($ComputerName)).AddressList)
                    if ($Results.Count -ne 0) {
                       ForEach ($Result in $Results) {
                           # make sure the returned result is IPv4
                           if ($Result.AddressFamily -eq 'InterNetwork') {
                               $Computers += $Result.IPAddressToString
                           }
                       }
                    }
                }
            }
            Catch {
                continue
            }
        }
    }
    $Computers
}

function Invoke-Threaded {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$True)]
        [String[]]
        $Computers,

        [Parameter(Position=1,Mandatory=$True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Parameter(Position=2)]
        [Hashtable]
        $ScriptParameters,

        [Int]
        $Threads = 20,

        [Switch]
        $NoImports
    )

    Begin {
        $ErrorActionPreference = 'SilentlyContinue'
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        if(!$NoImports) {
            $MyVars = Get-Variable -Scope 2

            $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")

            ForEach($Var in $MyVars) {
                if($VorbiddenVars -NotContains $Var.Name) {
                $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }

            Try {
                ForEach($Function in (Get-ChildItem Function:)) {
                    $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
                }
            } Catch {}
        }

        $Pool = [runspacefactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()

        $_Threads = @()
    }

    Process {
        ForEach ($Computer in $Computers) {
            $PS = [powershell]::Create()
            $Null = $PS.AddScript($ScriptBlock).AddParameter('IP', $Computer)

            if($ScriptParameters) {
                ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                    $Null = $PS.AddParameter($Param.Name, $Param.Value)
                }
            }
            $PS.runspacepool = $Pool
            $_Threads += @{
                instance = $PS
                handle = $PS.begininvoke()
            }
        }
    }

    End {
        $notdone = $true
        while ($notdone) {
            $notdone = $false
            for ($i=0; $i -lt $_Threads.count; $i++) {
                $thread = $_Threads[$i]
                if ($thread) {
                    if ($thread.handle.iscompleted) {
                        $thread.instance.endinvoke($thread.handle)
                        $thread.instance.dispose()
                        $_Threads[$i] = $null
                    }
                    else {
                        $notdone = $true
                    }
                }
            }
        }
    }
}

function Invoke-TestPort {
    Param(
        [parameter(Mandatory = $True)]
        [string]
        $IP,

        [parameter(Mandatory = $True)]
        [Int]
        $Port,

        [Int]
        $TimeOut = 1000
    )

    Try {
        $socket = new-object Net.Sockets.TcpClient;
        $connect = $socket.BeginConnect($IP, $Port, $null, $null)
        $NoTimeOut = $connect.AsyncWaitHandle.WaitOne($TimeOut, $false)

        if ($NoTimeOut) {
            $socket.EndConnect($connect) | Out-Null
            $socket.Close()
            return $true
        } else {
            $socket.Close()
            return $false
        }
    }
    Catch {
        return $false
    }
}

function Invoke-ClearPowershellLog {
    [CmdletBinding()] Param()
    Clear-EventLog -LogName "Windows PowerShell" -ErrorAction SilentlyContinue
}

function Invoke-GetDotNetVersion {
    $ListDotnet = @()

    $lists = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse |
    Get-ItemProperty -name Version,Release -EA 0 |
    Where { $_.PSChildName -match '^(?!S)\p{L}'} | Select PSChildName, Version, Release

	foreach ($item in $lists) {
		$ListDotnet += $item.Version
	}
	$ListDotnet
}
Export-ModuleMember -Function *