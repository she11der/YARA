rule MALPEDIA_Win_Wscspl_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f31d95be-4f0b-51e3-8f5f-15d1afc6eb9e"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wscspl"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.wscspl_auto.yar#L1-L117"
		license_url = "N/A"
		logic_hash = "4a0c5de1937bca874bba721d790f101d8b394ac870591bd7e9ae3e7dc3c9255d"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 740b b855000000 66a3???????? 8b4c2404 51 }
		$sequence_1 = { 8bcd 8d742414 8d442418 e8???????? 0fbf442414 50 8d4c241c }
		$sequence_2 = { 8d442430 50 68???????? 6a00 6a00 c744244000000000 }
		$sequence_3 = { 8b74240c 3bf7 7435 8b3d???????? 8d4900 8b4618 8b4004 }
		$sequence_4 = { 8d642400 8b0c18 8d1418 bf05000000 }
		$sequence_5 = { 3bc1 763a 03c9 3bc1 }
		$sequence_6 = { 663bf8 752f e8???????? 8b0d???????? }
		$sequence_7 = { 51 ff15???????? ff15???????? 6888130000 }
		$sequence_8 = { 8b1d???????? 55 33c0 56 83c1fb }
		$sequence_9 = { 687c230000 8d44240c 6a01 50 ff15???????? 687c230000 68c10b0000 }

	condition:
		7 of them and filesize <901120
}
