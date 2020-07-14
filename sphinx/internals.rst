Internals of Xenium LLMNR Responder
===================================

Interface managers
------------------

.. cpp:namespace:: xllmnrd

.. cpp:class:: interface_manager

.. cpp:function:: protected: \
                  interface_manager::interface_manager()

.. cpp:function:: virtual interface_manager::~interface_manager()

.. cpp:class:: rtnetlink_interface_manager: public interface_manager

   Interface managers for Linux.

   This implementation uses an RTNETLINK socket to communicate with the kernel.

.. cpp:function:: rtnetlink_interface_manager::rtnetlink_interface_manager()

.. cpp:function:: rtnetlink_interface_manager::~rtnetlink_interface_manager()

.. cpp:function:: virtual void rtnetlink_interface_manager::refresh(bool maybe_asynchronous = false) override
