static int
arch_get_scno(struct tcb *tcp)
{
	// XXX
	// if gdbserver
	//   tcp->scno already filled in
	return 1;
	// else #include_next...
}
