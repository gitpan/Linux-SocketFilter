#  You may distribute under the terms of either the GNU General Public License
#  or the Artistic License (the same terms as Perl itself)
#
#  (C) Paul Evans, 2010 -- leonerd@leonerd.org.uk

package Linux::SocketFilter::Assembler;

use strict;
use warnings;

our $VERSION = '0.02';

use Linux::SocketFilter qw( :bpf pack_sock_filter SKF_NET_OFF );

use Exporter 'import';
our @EXPORT_OK = qw(
   assemble
);

=head1 NAME

C<Linux::SocketFilter::Assembler> - assemble BPF programs from textual code

=head1 DESCRIPTION

Linux sockets allow a filter to be attached, which determines which packets
will be allowed through, and which to block. They are most often used on
C<PF_PACKET> sockets when used to capture network traffic, as a filter to
determine the traffic of interest to the capturing application. The filter is
a program run in a simple virtual machine, which can inspect bytes of the
packet and certain other items of metadata, and returns the number of bytes
to capture (or zero, to indicate this packet should be ignored).

This module allows filter programs to be written in textual code, and
assembled into a binary filter, to attach to the socket using the
C<SO_ATTACH_FILTER> socket option.

While reading this documentation, the reader is assumed to have a basic
knowledge of the C<PF_PACKET> socket family, the Berkeley Packet Filter, and
its extensions in Linux.

=cut

=head1 FUNCTIONS

=cut

=head2 $filter = assemble( $text )

Takes a program (fragment) in text form and returns a binary string
representing the instructions packed ready for C<attach_filter()>.

The program consists of C<\n>-separated lines of instructions or comments.
Leading whitespace is ignored. Blank lines are ignored. Lines beginning with
a C<;> (after whitespace) are ignored as comments.

=cut

sub assemble
{
   my $self = __PACKAGE__;
   my ( $text ) = @_;

   my $ret = "";

   foreach ( split m/\n/, $text ) {
      s/^\s+//;      # trim whitespace
      next if m/^$/; # skip blanks
      next if m/^;/; # skip comments

      my ( $op, $args ) = split ' ', $_, 2;
      my @args = split m/,\s*/, $args;

      $self->can( "assemble_$op" ) or
         die "Can't compile $_ - unrecognised op '$op'\n";

      $ret .= $self->${\"assemble_$op"}( @args );
   }

   return $ret;
}

=head1 INSTRUCTION FORMAT

Each instruction in the program is formed of an opcode followed by at least
one operand. Where numeric literals are involved, they may be given in
decimal, hexadecimal, or octal form. Literals will be notated as C<lit> in the
following descriptions.

=cut

my $match_literal = qr/-?(?:\d+|0x[0-9a-f]+)/;
sub _parse_literal
{
   my ( $lit ) = @_;

   my $sign = ( $lit =~ s/^-// ) ? -1 : 1;

   return $sign * oct( $lit ) if $lit =~ m/^0x?/; # oct can manage octal or hex
   return $sign * int( $lit ) if $lit =~ m/\d+/;

   die "Cannot parse literal $lit\n";
}

=pod

 LD BYTE[addr]
 LD HALF[addr]
 LD WORD[addr]

Load the C<A> register from the 8, 16, or 32 bit quantity in the packet buffer
at the address. The address may be given in the forms

 lit
 X+lit
 NET+lit
 NET+X+lit

To load from an immediate or C<X>-index address, starting from either the
beginning of the buffer, or the beginning of the network header, respectively.

 LD len

Load the C<A> register with the length of the packet.

 LD lit

Load the C<A> register with a literal value

 LD M[lit]

Load the C<A> register with the value from the given scratchpad cell

 LD X

Load the C<A> register with the value from the C<X> register.

=cut

sub assemble_LD
{
   my ( undef, $src ) = @_;

   my $code = BPF_LD;

   if( $src =~ m/^(BYTE|HALF|WORD)\[(NET\+)?(X\+)?($match_literal)]$/ ) {
      my ( $size, $net, $x, $offs ) = ( $1, $2, $3, _parse_literal($4) );

      $code |= ( $size eq "BYTE" ) ? BPF_B :
               ( $size eq "HALF" ) ? BPF_H :
                                     BPF_W;
      $code |= ( $x ) ? BPF_IND :
                        BPF_ABS;

      $offs += SKF_NET_OFF if $net;

      pack_sock_filter( $code, 0, 0, $offs );
   }
   elsif( $src eq "len" ) {
      pack_sock_filter( $code|BPF_W|BPF_LEN, 0, 0, 0 );
   }
   elsif( $src =~ m/^$match_literal$/ ) {
      pack_sock_filter( $code|BPF_IMM, 0, 0, _parse_literal($src) );
   }
   elsif( $src =~ m/^M\[($match_literal)\]$/ ) {
      pack_sock_filter( $code|BPF_MEM, 0, 0, _parse_literal($1) );
   }
   elsif( $src eq "X" ) {
      pack_sock_filter( BPF_MISC|BPF_TAX, 0, 0, 0 );
   }
   else {
      die "Unrecognised instruction LD $src\n";
   }
}

=pod

 LDX lit

Load the C<X> register with a literal value

 LDX M[lit]

Load the C<X> register with the value from the given scratchpad cell

 LDX A

Load the C<X> register with the value from the C<A> register

=cut

sub assemble_LDX
{
   my ( undef, $src ) = @_;

   my $code = BPF_LDX;

   if( $src =~ m/^$match_literal$/ ) {
      pack_sock_filter( $code|BPF_IMM, 0, 0, _parse_literal($src) );
   }
   elsif( $src =~ m/^M\[($match_literal)\]$/ ) {
      pack_sock_filter( $code|BPF_MEM, 0, 0, _parse_literal($1) );
   }
   elsif( $src eq "A" ) {
      pack_sock_filter( BPF_MISC|BPF_TXA, 0, 0, 0 );
   }
   else {
      die "Unrecognised instruction LDX $src\n";
   }
}

=pod

 ST M[lit]

Store the value of the C<A> register into the given scratchpad cell

 STX M[lit]

Store the value of the C<X> register into the given scratchpad cell

=cut

sub assemble_ST  { shift->assemble_store( BPF_ST,  @_ ) }
sub assemble_STX { shift->assemble_store( BPF_STX, @_ ) }
sub assemble_store
{
   my ( undef, $code, $dest ) = @_;

   if( $dest =~ m/^M\[($match_literal)\]$/ ) {
      pack_sock_filter( $code, 0, 0, _parse_literal($1) );
   }
   else {
      die "Unrecognised instruction ST(X?) $dest\n";
   }
}

=pod

 ADD src   # A = A + src
 SUB src   # A = A - src
 MUL src   # A = A * src
 DIV src   # A = A / src
 AND src   # A = A & src
 OR src    # A = A | src
 LSH src   # A = A << src
 RSH src   # A = A >> src

Perform arithmetic or bitwise operations. In each case, the operands are the
C<A> register and the given source, which can be either the C<X> register or
a literal. The result is stored in the C<A> register.

=cut

sub assemble_ADD { shift->assemble_alu( BPF_ADD, @_ ) }
sub assemble_SUB { shift->assemble_alu( BPF_SUB, @_ ) }
sub assemble_MUL { shift->assemble_alu( BPF_MUL, @_ ) }
sub assemble_DIV { shift->assemble_alu( BPF_DIV, @_ ) }
sub assemble_AND { shift->assemble_alu( BPF_AND, @_ ) }
sub assemble_OR  { shift->assemble_alu( BPF_OR,  @_ ) }
sub assemble_LSH { shift->assemble_alu( BPF_LSH, @_ ) }
sub assemble_RSH { shift->assemble_alu( BPF_RSH, @_ ) }
sub assemble_alu
{
   my ( undef, $code, $val ) = @_;

   $code |= BPF_ALU;
   if( $val eq "X" ) {
      pack_sock_filter( $code|BPF_X, 0, 0, 0 );
   }
   elsif( $val =~ m/^$match_literal$/ ) {
      pack_sock_filter( $code|BPF_K, 0, 0, _parse_literal($val) );
   }
   else {
      die "Unrecognised alu instruction on $val\n";
   }
}

=pod

 JGT src, jt, jf   # test if A > src
 JGE src, jt, jf   # test if A >= src
 JEQ src, jt, jf   # test if A == src
 JSET src, jt, jf  # test if A & src is non-zero

Jump conditionally based on comparisons between the C<A> register and the
given source, which is either the C<X> register or a literal. If the
comparison is true, the C<jt> branch is taken; if false the C<jf>. Each branch
is a numeric count of the number of instructions to skip forwards.

=cut

sub assemble_JGT  { shift->assemble_jmp( BPF_JGT,  @_ ) }
sub assemble_JGE  { shift->assemble_jmp( BPF_JGE,  @_ ) }
sub assemble_JSET { shift->assemble_jmp( BPF_JSET, @_ ) }
sub assemble_JEQ  { shift->assemble_jmp( BPF_JEQ,  @_ ) }
sub assemble_jmp
{
   my ( undef, $code, $val, $jt, $jf ) = @_;

   $code |= BPF_JMP;
   if( $val eq "X" ) {
      pack_sock_filter( $code|BPF_X, $jt, $jf, 0 );
   }
   elsif( $val =~ m/^$match_literal$/ ) {
      pack_sock_filter( $code|BPF_K, $jt, $jf, _parse_literal($val) );
   }
   else {
      die "Unrecognised jmp instruction on $val\n";
   }
}

=pod

 JA jmp

Jump unconditionally forward by the given number of instructions.

=cut

sub assemble_JA
{
   my ( undef, $target ) = @_;
   pack_sock_filter( BPF_JMP, 0, 0, $target+0 );
}

=pod

 RET lit

Terminate the filter program and return the literal value to the kernel.

 RET A

Terminate the filter program and return the value of the C<A> register to the
kernel.

=cut

sub assemble_RET
{
   my ( undef, $val ) = @_;

   my $code = BPF_RET;

   if( $val =~ m/^$match_literal$/ ) {
      pack_sock_filter( $code|BPF_K, 0, 0, _parse_literal($val) );
   }
   elsif( $val eq "A" ) {
      pack_sock_filter( $code|BPF_A, 0, 0, 0 );
   }
   else {
      die "Unrecognised instruction RET $val\n";
   }
}

# Keep perl happy; keep Britain tidy
1;

=head1 AUTHOR

Paul Evans <leonerd@leonerd.org.uk>
