#  You may distribute under the terms of either the GNU General Public License
#  or the Artistic License (the same terms as Perl itself)
#
#  (C) Paul Evans, 2010 -- leonerd@leonerd.org.uk

package Linux::SocketFilter;

use strict;
use warnings;

use Carp;

our $VERSION = '0.03';

use Exporter 'import';

use Socket qw( SOL_SOCKET );

BEGIN { require Linux::SocketFilter_const; }
use constant SIZEOF_SOCK_FILTER => length pack_sock_filter( 0, 0, 0, 0 );

push our @EXPORT_OK, qw(
   attach_filter
   detach_filter
);

our %EXPORT_TAGS = (
   bpf => [ do { no strict 'refs'; grep m/^BPF_/, keys %{__PACKAGE__."::"} } ]
);

=head1 NAME

C<Linux::SocketFilter> - interface to Linux's socket packet filtering

=head1 DESCRIPTION

This module contains the constants and structure definitions to use Linux's
socket packet filtering mechanism.

=head1 CONSTANTS

The following constants are exported:

=head2 Socket Options

 SO_ATTACH_FILTER SO_DETACH_FILTER

=head2 BPF Instructions

 BPF_LD BPF_LDX BPF_ST BPF_STX BPF_ALU BPF_JMP BPF_RET BPF_MISC
 BPF_W BPF_H BPF_B BPF_IMM BPF_ABS BPF_IND BPF_MEM PBF_LEN BPF_MSH
 BPF_ADD BPF_SUB BPF_MUL BPF_DIV BPF_OR BPF_AND BPF_LSH BPF_RSH BPF_NEG
 BPF_JA BPF_JEQ BPF_JGT BPF_JGE BPF_JSET
 BPF_K BPF_X BPF_A BPF_TAX BPF_TXA

This entire set of constants is also exported under the tag name C<:bpf>.

=head2 Linux BPF Extension Packet Addresses

 SKF_AD_OFF SKF_AD_PROTOCOL SKF_AD_PKTTYPE SKF_AD_IFINDEX
 SKF_NET_OFF SKF_LL_OFF

=head1 STRUCTURE FUNCTIONS

=head2 $buffer = pack_sock_filter( $code, $jt, $jf, $k )

=head2 ( $code, $jt, $jf, $k ) = unpack_sock_filter( $buffer )

Pack or unpack a single BPF instruction.

=cut

=head1 SOCKET FUNCTIONS

=cut

=head2 attach_filter( $sock, $filter )

Attaches the given filter program to the given socket. The program should be a
string formed by concatenating multiple calls to C<pack_sock_filter()> to
build the filter program.

=cut

sub attach_filter
{
   my ( $sock, $filter ) = @_;

   my $fbytes = length $filter;
   ( $fbytes % SIZEOF_SOCK_FILTER ) == 0 or
      croak "Expected filter to be a multiple of ".SIZEOF_SOCK_FILTER." bytes";

   my $flen = $fbytes / SIZEOF_SOCK_FILTER;

   # TODO: ExtUtils::H2PM can't make this sort of function
   my $struct_sock_fprog = pack( "S x![P] P", $flen, $filter );

   $sock->setsockopt( SOL_SOCKET, SO_ATTACH_FILTER, $struct_sock_fprog );
}

=head2 detach_filter( $sock )

Detaches the current filter from the socket, returning it to accepting all
packets.

=cut

sub detach_filter
{
   my ( $sock ) = @_;

   # We don't care about an option value, but kernel requires optlen to be at
   # least sizeof(int).
   $sock->setsockopt( SOL_SOCKET, SO_DETACH_FILTER, pack( "I", 0 ) );
}

# Keep perl happy; keep Britain tidy
1;

=head1 AUTHOR

Paul Evans <leonerd@leonerd.org.uk>
