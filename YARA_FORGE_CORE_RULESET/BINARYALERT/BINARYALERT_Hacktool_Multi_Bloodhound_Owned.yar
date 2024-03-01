rule BINARYALERT_Hacktool_Multi_Bloodhound_Owned
{
	meta:
		description = "Bloodhound: Custom queries to document a compromise, find collateral spread of owned nodes, and visualize deltas in privilege gains"
		author = "@fusionrace"
		id = "4d458339-6589-5094-8c23-1ad2baee19f1"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://github.com/porterhau5/BloodHound-Owned/"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/multi/hacktool_multi_bloodhound_owned.yara#L1-L20"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "01ef15a3cd606c46dacb0f22477fe97f94e212a38af1cd5bdd7eb11efe8144dd"
		score = 75
		quality = 80
		tags = ""

	strings:
		$s1 = "Find all owned Domain Admins" fullword ascii wide
		$s2 = "Find Shortest Path from owned node to Domain Admins" fullword ascii wide
		$s3 = "List all directly owned nodes" fullword ascii wide
		$s4 = "Set owned and wave properties for a node" fullword ascii wide
		$s5 = "Find spread of compromise for owned nodes in wave" fullword ascii wide
		$s6 = "Show clusters of password reuse" fullword ascii wide
		$s7 = "Something went wrong when creating SharesPasswordWith relationship" fullword ascii wide
		$s8 = "reference doc of custom Cypher queries for BloodHound" fullword ascii wide
		$s9 = "Created SharesPasswordWith relationship between" fullword ascii wide
		$s10 = "Skipping finding spread of compromise due to" fullword ascii wide

	condition:
		any of them
}
