#!/usr/bin/perl -w

@data=("\tA|B\tA|B\tA|B\tA|B","\tA|B\tB\tn\tn","\tA|B\tn\tn\tn","\tA|B\tB\tB\tA|B","\tA|B\tn\tn\tA|B","\tB\tn\tn\tn","\tB\tB\tn\tn","\tn\tn\tn\tn");
@trailer=("n\tA\tA\tn\tA\tA","n\tB\tA|B\tn\tn\tB","n\tn\tA\tn\tA\tn","n\tn\tA|B\tn\tn\tn","n\tA\tA\tA\tA\tA","n\tn\tA|B\tB\tn\tn","n\tB\tA|B\tB\tn\tB","n\tn\tA|B\tn\tn\tn");

if ($#ARGV<0) {
    print("Usage:\tnfc_access.pl 0x<byte6> 0x<byte7> 0x<byte8>\n or \tnfc_access.pl <byte6>:<byte7>:<byte8>\n\n");
    exit 1;
}

if ($#ARGV==0) {
    if ($ARGV[0]=~/(\w{2}):(\w{2}):(\w{2})/) {
	print $1," ",$2," ",$3,"\n";
	    $b6=hex($1);
	    $b7=hex($2);
	    $b8=hex($3);
	}
}else{
    $b6=hex($ARGV[0]);
    $b7=hex($ARGV[1]);
    $b8=hex($ARGV[2]);
}

printf("%d %d %d\n",$b6,$b7,$b8);

$nc1_0=($b6&0x01)?1:0;
$nc1_1=($b6&0x02)?1:0;
$nc1_2=($b6&0x04)?1:0;
$nc1_3=($b6&0x08)?1:0;
$nc2_0=($b6&0x10)?1:0;
$nc2_1=($b6&0x20)?1:0;
$nc2_2=($b6&0x40)?1:0;
$nc2_3=($b6&0x80)?1:0;
$nc3_0=($b7&0x01)?1:0;
$nc3_1=($b7&0x02)?1:0;
$nc3_2=($b7&0x04)?1:0;
$nc3_3=($b7&0x08)?1:0;

$c1_0=($b7&0x10)?1:0;
$c1_1=($b7&0x20)?1:0;
$c1_2=($b7&0x40)?1:0;
$c1_3=($b7&0x80)?1:0;
$c2_0=($b8&0x01)?1:0;
$c2_1=($b8&0x02)?1:0;
$c2_2=($b8&0x04)?1:0;
$c2_3=($b8&0x08)?1:0;
$c3_0=($b8&0x10)?1:0;
$c3_1=($b8&0x20)?1:0;
$c3_2=($b8&0x40)?1:0;
$c3_3=($b8&0x80)?1:0;

$bl0ok=1;
$bl1ok=1;
$bl2ok=1;
$bl3ok=1;

if (!($nc1_0 ^ $c1_0)) {printf("Block 0 access error\n");$bl0ok=0;}
if (!($nc1_1 ^ $c1_1)) {printf("Block 1 access error\n");$bl1ok=0;}
if (!($nc1_2 ^ $c1_2)) {printf("Block 2 access error\n");$bl2ok=0;}
if (!($nc1_3 ^ $c1_3)) {printf("Block 3 access error\n");$bl3ok=0;}
if (!($nc2_0 ^ $c2_0)) {printf("Block 0 access error\n");$bl0ok=0;}
if (!($nc2_1 ^ $c2_1)) {printf("Block 1 access error\n");$bl1ok=0;}
if (!($nc2_2 ^ $c2_2)) {printf("Block 2 access error\n");$bl2ok=0;}
if (!($nc2_3 ^ $c2_3)) {printf("Block 3 access error\n");$bl3ok=0;}
if (!($nc3_0 ^ $c3_0)) {printf("Block 0 access error\n");$bl0ok=0;}
if (!($nc3_1 ^ $c3_1)) {printf("Block 1 access error\n");$bl1ok=0;}
if (!($nc3_2 ^ $c3_2)) {printf("Block 2 access error\n");$bl2ok=0;}
if (!($nc3_3 ^ $c3_3)) {printf("Block 3 access error\n");$bl3ok=0;}

print "\tread\twrite\tincr\td,t,r\n";
if ($bl0ok) {printf("Blk0%s\n",$data[$c1_0|($c2_0<<1)|($c3_0<<2)]);} else {print("Block 0 access error\n");}
if ($bl1ok) {printf("Blk1%s\n",$data[$c1_1|($c2_1<<1)|($c3_1<<2)]);} else {print("Block 1 access error\n");}
if ($bl2ok) {printf("Blk2%s\n",$data[$c1_2|($c2_2<<1)|($c3_2<<2)]);} else {print("Block 2 access error\n");}

print "\nKey A\t\tAccess bits\tKey B\n";
print "rd\twr\trd\twr\trd\twr\n";
if ($bl3ok) {printf("%s\n",$trailer[$c1_3|($c2_3<<1)|($c3_3<<2)]);} else {print("Trailer access error\n");}





