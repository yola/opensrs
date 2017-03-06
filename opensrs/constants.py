AUTO_RENEWED_TLDS = ('de', 'dk', 'za', 'at', 'fr')


class OrderProcessingMethods(object):
    """Indicates how to process the order.

    process: Proceed with the order immediately.
    save: Pend the order for later approval by the RSP.

    """
    PROCESS = 'process'
    SAVE = 'save'
