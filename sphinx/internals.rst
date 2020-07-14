Internals of Xenium LLMNR Responder
===================================

Interface managers
------------------

.. cpp:namespace:: xllmnrd

.. cpp:class:: interface_manager

   This is an abstract class of interface managers.

   .. cpp:function:: interface_manager()
                     interface_manager(const interface_manager &) = delete

      [protected]
      Constructs an interface manager object.

      The copy constructor is deleted.

   .. cpp:function:: void operator =(const interface_manager &) = delete

      The copy assignment operator is deleted.

   .. cpp:function:: virtual ~interface_manager()

      Destructs an interface manager object.

   .. cpp:function:: int debug_level() const

      Returns the current debug level of the interface manager object.
      The debug level controls the verbosity of debug logs to be emitted.
      The default debug level is 0.

   .. cpp:function:: void set_debug_level(int debug_level)

      Sets the current debug level of the interface manager object.

   .. cpp:function:: void add_interface_listener(interface_listener *listener)

   .. cpp:function:: void remove_interface_listener(interface_listener *listener)

   .. cpp:function:: std::set<in_addr> in_addresses(unsigned int interface_index) const

   .. cpp:function:: std::set<in6_addr> in6_addresses(unsigned int interface_index) const

   .. cpp:function:: virtual void refresh(bool maybe_asynchronous = false) = 0

   .. cpp:function:: void remove_interfaces()

      [protected]

   .. cpp:function:: void enable_interface(unsigned int interface_index)

      [protected]

   .. cpp:function:: void disable_interface(unsigned int interface_index)

      [protected]

   .. cpp:function:: void add_interface_address(unsigned int interface_index, \
                         int address_family, const void *address, size_t address_size)

      [protected]

   .. cpp:function:: void remove_interface_address(unsigned int interface_index, \
                         int address_family, const void *address, size_t address_size)

      [protected]


.. cpp:class:: rtnetlink_interface_manager: public interface_manager

   RTNETLINK-based interface manager objects for Linux.

   This implementation uses an RTNETLINK socket to communicate with the kernel.

   .. cpp:function:: rtnetlink_interface_manager()

      Constructs an RTNETLINK-based interface manager object.

   .. cpp:function:: virtual ~rtnetlink_interface_manager()

      Destructs an RTNETLINK-based interface manager object.

   .. cpp:function:: virtual void refresh(bool maybe_asynchronous = false) override


Responders
----------

.. cpp:namespace:: 0

.. cpp:class:: responder

   This is a class of LLMNR responders.

   .. cpp:function:: responder()
                     explicit responder(in_port_t port)

      Constructs a responder object.

   .. cpp:function:: ~responder()

      Destructs a responder object.
