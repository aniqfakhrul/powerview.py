#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : iconfigset.py
# Author             : Podalirius (@podalirius_)
# Date created       : 1 Aug 2021

from enum import Enum


class MergeRules(Enum):
    """
    MergeRules
    Merge rules for merging config sets.
    """

    # Throw an exception if a merge causes a parameter to be overwritten with a different value in the destination config set.
    ThrowOnConflicts = 0

    # Overwrite destination config set.
    Overwrite = 1

    # Keep existing values of the destination config set intact while performing the merge.
    KeepExisting = 2

"""
# Interface definition for a config set.
public interface IConfigSet : IEnumerable<KeyValuePair<int, object>>
{
    # <summary>
    # Gets a particular config parameter's value.
    # </summary>
    # <param name="key">The parameter to get.</param>
    # <returns>The requested parameter's value.</returns>
    object this[int key] { get; }

    # <summary>
    # Gets a particular config parameter's value.
    # </summary>
    # <param name="key">The parameter to get.</param>
    # <param name="value">The requested parameter's value.</param>
    # <returns>true if the value was found, false otherwise.</returns>
    bool TryGetValue(int key, out object value);

    # <summary>
    # Merges two config sets into one and throws an exception if there are any conflicts.
    # </summary>
    # <param name="source">The MergeSource config set to user.</param>
    void Merge(IConfigSet source);

    # <summary>
    # Merges two config sets into one.
    # </summary>
    # <param name="source">The MergeSource config set to user.</param>
    # <param name="mergeRule">The merge rule to use.</param>
    void Merge(IConfigSet source, MergeRules mergeRule);
}
"""


class ConfigSetMergeException(Exception):
    """
    ConfigSetMergeException

    Represents exceptions thrown while merging two config sets.
    """

    # Gets the MergeSource config set used during the merge operation.
    MergeSource:IConfigSet = None

    # Gets the destination config set used during the merge operation.
    MergeDest: IConfigSet = None

    def __init__(self, mergeSource:IConfigSet, mergeDest:IConfigSet, message:str):
        """
        Initializes a new instance of the ConfigSetMergeException class.

        <param name="mergeSource">The MergeSource config set.</param>
        <param name="mergeDest">The destination config set.</param>
        <param name="message">The exception message.</param>
        <param name="inner">The inner exception.</param>
        """
        self.MergeSource = mergeSource
        self.MergeDest = mergeDest
