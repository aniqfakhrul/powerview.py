#!/usr/bin/env python3

EDRS = [
	{
	  "name": "Bitdefender",
	  "services": [
	    {
	      "name": "bdredline_agent",
	      "description": "Bitdefender Agent RedLine Service"
	    },
	    {
	      "name": "BDAuxSrv",
	      "description": "Bitdefender Auxiliary Service"
	    },
	    {
	      "name": "UPDATESRV",
	      "description": "Bitdefender Desktop Update Service"
	    },
	    {
	      "name": "VSSERV",
	      "description": "Bitdefender Virus Shield"
	    },
	    {
	      "name": "bdredline",
	      "description": "Bitdefender RedLine Service"
	    }
	  ],
	  "pipes": [
	    {
	      "name": "local\\msgbus\\antitracker.low\\*",
	      "processes": [
	        "bdagent.exe"
	      ]
	    },
	    {
	      "name": "local\\msgbus\\aspam.actions.low\\*",
	      "processes": [
	        "bdagent.exe"
	      ]
	    },
	    {
	      "name": "local\\msgbus\\bd.process.broker.pipe",
	      "processes": [
	        "bdagent.exe",
	        "bdservicehost.exe",
	        "updatesrv.exe"
	      ]
	    },
	    {
	      "name": "local\\msgbus\\bdagent*",
	      "processes": [
	        "bdagent.exe"
	      ]
	    },
	    {
	      "name": "local\\msgbus\\bdauxsrv",
	      "processes": [
	        "bdagent.exe",
	        "bdntwrk.exe"
	      ]
	    }
	  ]
	},
	{
	  "name": "Windows Defender",
	  "services": [
	    {
	      "name": "WinDefend",
	      "description": "Windows Defender Antivirus Service"
	    },
	    {
	      "name": "Sense",
	      "description": "Windows Defender Advanced Threat Protection Service"
	    },
	    {
	      "name": "WdNisSvc",
	      "description": "Windows Defender Antivirus Network Inspection Service"
	    },
	    {
	    	"name": "WdNisDrv",
	    	"description": "Windows Defender Antivirus Network Inspection System Driver"
	    }
	  ],
	  "pipes": []
	},
	{
	  "name": "ESET",
	  "services": [
	    {
	      "name": "ekm",
	      "description": "ESET"
	    },
	    {
	      "name": "epfw",
	      "description": "ESET"
	    },
	    {
	      "name": "epfwlwf",
	      "description": "ESET"
	    },
	    {
	      "name": "epfwwfp",
	      "description": "ESET"
	    },
	    {
	      "name": "EraAgentSvc",
	      "description": "ESET"
	    }
	  ],
	  "pipes": [
	    {
	      "name": "nod_scriptmon_pipe",
	      "processes": [
	        ""
	      ]
	    }
	  ]
	},
	{
	  "name": "CrowdStrike",
	  "services": [
	    {
	      "name": "CSFalconService",
	      "description": "CrowdStrike Falcon Sensor Service"
	    }
	  ],
	  "pipes": [
	    {
	      "name": "CrowdStrike\\{*",
	      "processes": [
	        "CSFalconContainer.exe",
	        "CSFalconService.exe"
	      ]
	    }
	  ]
	},
	{
	  "name": "SentinelOne",
	  "services": [
	    {
	      "name": "SentinelAgent",
	      "description": "SentinelOne Endpoint Protection Agent"
	    },
	    {
	      "name": "SentinelStaticEngine",
	      "description": "Manage static engines for SentinelOne Endpoint Protection"
	    },
	    {
	      "name": "LogProcessorService",
	      "description": "Manage logs for SentinelOne Endpoint Protection"
	    },
	    {
	    	"name": "SentinelHelperService",
	    	"description": "SentinelOne Helper Service"
	    }
	  ],
	  "pipes": [
	    {
	      "name": "SentinelAgentWorkerCert.*",
	      "processes": [
	        ""
	      ]
	    },
	    {
	      "name": "DFIScanner.Etw.*",
	      "processes": [
	        "SentinelStaticEngine.exe"
	      ]
	    },
	    {
	      "name": "DFIScanner.Inline.*",
	      "processes": [
	        "SentinelAgent.exe"
	      ]
	    }
	  ]
	},
	{
	  "name": "Carbon Black App Control",
	  "services": [
	    {
	      "name": "Parity",
	      "description": "Carbon Black App Control Agent"
	    }
	  ],
	  "pipes": []
	},
	{
	  "name": "Cybereason",
	  "services": [
	    {
	      "name": "CybereasonActiveProbe",
	      "description": "Cybereason Active Probe"
	    },
	    {
	      "name": "CybereasonCRS",
	      "description": "Cybereason Anti-Ransomware"
	    },
	    {
	      "name": "CybereasonBlocki",
	      "description": "Cybereason Execution Prevention"
	    }
	  ],
	  "pipes": [
	    {
	      "name": "CybereasonAPConsoleMinionHostIpc_*",
	      "processes": [
	        "minionhost.exe"
	      ]
	    },
	    {
	      "name": "CybereasonAPServerProxyIpc_*",
	      "processes": [
	        "minionhost.exe"
	      ]
	    }
	  ]
	},
	{
	  "name": "Symantec Endpoint Protection",
	  "services": [
	    {
	      "name": "SepMasterService",
	      "description": "Symantec Endpoint Protection"
	    },
	    {
	      "name": "SepScanService",
	      "description": "Symantec Endpoint Protection Scan Services"
	    },
	    {
	      "name": "SNAC",
	      "description": "Symantec Network Access Control"
	    }
	  ],
	  "pipes": []
	},
	{
	  "name": "Carbon Black",
	  "services": [
	    {
	      "name": "CbDefense",
	      "description": "Carbon Black Cloud Sensor service"
	    },
	    {
	      "name": "CbDefenseWSC",
	      "description": "Carbon Black Cloud Sensor WSC service"
	    }
	  ],
	  "pipes": []
	},
	{
	  "name": "SysMon",
	  "services": [
	    {
	      "name": "Sysmon64",
	      "description": "System Monitor service"
	    },
		{
	      "name": "Sysmon",
	      "description": "System Monitor service"
	    }
	  ],
	  "pipes": []
	},
	{
		"name": "Trend Micro",
		"services": [
			{
				"name": "ds_agent",
				"description": "Trend Micro Deep Security Agent"
			}
		],
		"pipes": []
	},
	{
	  "name": "Sophos Intercept X",
	  "services": [
	    {
	      "name": "SntpService",
	      "description": "Sophos Network Threat Protection"
	    },
	    {
	      "name": "Sophos Endpoint Defense Service",
	      "description": "Sophos Endpoint Defense Service"
	    },
	    {
	      "name": "Sophos File Scanner Service",
	      "description": "Sophos File Scanner Service"
	    },
	    {
	      "name": "Sophos Health Service",
	      "description": "Sophos Health Service"
	    },
	    {
	      "name": "Sophos Live Query",
	      "description": "Sophos Live Query"
	    },
	    {
	      "name": "Sophos Managed Threat Response",
	      "description": "Sophos Managed Threat Response"
	    },
	    {
	      "name": "Sophos MCS Agent",
	      "description": "Sophos MCS Agent"
	    },
	    {
	      "name": "Sophos MCS Client",
	      "description": "Sophos MCS Client"
	    },
	    {
	      "name": "Sophos System Protection Service",
	      "description": "Sophos System Protection Service"
	    }
	  ],
	  "pipes": []
	},
	{
		"name": "Cylance",
		"services": [
			{
				"name": "CylanceDrv",
				"description": "CylanceDrv"
			},
			{
				"name": "CylanceSvc",
				"description": "Cylance Unified Agent"
			},
			{
				"name": "CyOptics",
				"description": "Cylance Optics"
			},
			{
				"name": "CyOpticsDrv",
				"description": "CyOpticsDrv"
			},
			{
				"name": "CyProtectDrv",
				"description": "CyProtectDrv"
			}
		],
		"pipes": []
	},
	{
		"name": "Trend Micro",
		"services": [
			{
				"name": "TmPreFilter",
				"description": "Trend Micro PreFilter"
			},
			{
				"name": "tmumh",
				"description": "Trend Micro User Mode Hook Driver"
			},
			{
				"name": "tmusa",
				"description": "Trend Micro Osprey Driver"
			},
			{
				"name": "tmWfp",
				"description": "Trend Micro WFP Callout Driver"
			},
			{
				"name": "TmWSCSvc",
				"description": "Apex One NT WSC Service"
			},
			{
				"name": "Trend Micro Endpoint Basecamp",
				"description": "Trend Micro Endpoint Basecamp"
			},
			{
				"name": "Trend Micro Web Service Communicator",
				"description": "Trend Micro Web Service Communicator"
			}
		],
		"pipes": []
	}
]

class EDR:
	def __init__(self):
		self.names = []
		self.services = []

		for edr in EDRS:
			self.names.append(edr["name"])
			for svc in edr["services"]:
				self.services.append(svc["name"])

	def service_exist(self, product) -> bool:
		if product in self.services:
			return True
		else:
			return False