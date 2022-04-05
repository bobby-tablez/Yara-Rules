rule enemy_bot
{
	meta:
		description = "Detects EnemyBot Botnet Malware"
		author = "Tim Peck"
		reference = "https://www.securonix.com/blog/detecting-the-enemybot-botnet-advisory/"
		date: "2022/03/29"

	strings:
		$elf = { 7f 45 4c 46 }
		$s0 = "\x65\x6e\x65\x6d\x79"
		$s1 = "decodedshit"
		$s2 = "watudoinglookingatdis"

	condition:
		( $elf at 0 ) and all of ($s*)
}
