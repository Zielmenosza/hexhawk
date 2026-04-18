import React, { useState } from 'react';

interface Bookmark {
  id: string;
  address: number;
  note: string;
  tags: string[];
  timestamp: number;
}

interface BookmarksPanelProps {
  bookmarks: Bookmark[];
  onGoToBookmark: (bookmark: Bookmark) => void;
  onDeleteBookmark: (id: string) => void;
  onAddBookmark: (note: string) => void;
  currentAddress: number | null;
  formatHex: (n: number) => string;
}

export function BookmarksPanel({
  bookmarks,
  onGoToBookmark,
  onDeleteBookmark,
  onAddBookmark,
  currentAddress,
  formatHex,
}: BookmarksPanelProps) {
  const [newNote, setNewNote] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);

  const handleAddBookmark = () => {
    if (currentAddress === null) {
      alert('No address selected');
      return;
    }
    onAddBookmark(newNote);
    setNewNote('');
    setShowAddForm(false);
  };

  const sortedBookmarks = [...bookmarks].sort((a, b) => b.timestamp - a.timestamp);

  return (
    <div className="bookmarks-panel">
      <div className="bookmarks-header">
        <strong>🔖 Bookmarks ({bookmarks.length})</strong>
        <button
          type="button"
          className="add-bookmark-btn"
          onClick={() => setShowAddForm(!showAddForm)}
          disabled={currentAddress === null}
          title={currentAddress === null ? 'Select an address first' : 'Add bookmark at current address'}
        >
          +
        </button>
      </div>

      {showAddForm && (
        <div className="bookmark-add-form">
          <input
            type="text"
            placeholder="Bookmark note..."
            value={newNote}
            onChange={(e) => setNewNote(e.target.value)}
            className="bookmark-input"
            onKeyPress={(e) => {
              if (e.key === 'Enter') {
                handleAddBookmark();
              }
            }}
          />
          <div className="bookmark-form-buttons">
            <button
              type="button"
              className="btn-confirm"
              onClick={handleAddBookmark}
            >
              Add
            </button>
            <button
              type="button"
              className="btn-cancel"
              onClick={() => setShowAddForm(false)}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {sortedBookmarks.length === 0 ? (
        <div className="bookmarks-empty">
          <p>No bookmarks yet</p>
          <small>Select an address and click + to add one</small>
        </div>
      ) : (
        <div className="bookmarks-list">
          {sortedBookmarks.map((bookmark) => (
            <div key={bookmark.id} className="bookmark-row">
              <button
                type="button"
                className="bookmark-link"
                onClick={() => onGoToBookmark(bookmark)}
                title={`Jump to ${formatHex(bookmark.address)}`}
              >
                <span className="bookmark-addr">{formatHex(bookmark.address)}</span>
                <span className="bookmark-note">{bookmark.note || '(no note)'}</span>
              </button>
              <button
                type="button"
                className="bookmark-delete"
                onClick={() => {
                  if (confirm('Delete this bookmark?')) {
                    onDeleteBookmark(bookmark.id);
                  }
                }}
                title="Delete bookmark"
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
