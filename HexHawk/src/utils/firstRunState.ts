export const FIRST_RUN_LOADED_FILE_KEY = 'hexhawk.hasLoadedFile';

export function hasLoadedFileBefore(storage: Pick<Storage, 'getItem'> = localStorage): boolean {
  return storage.getItem(FIRST_RUN_LOADED_FILE_KEY) === 'true';
}

export function markLoadedFile(storage: Pick<Storage, 'setItem'> = localStorage): void {
  storage.setItem(FIRST_RUN_LOADED_FILE_KEY, 'true');
}

export function shouldShowFirstRunPanel(hasLoadedFile: boolean): boolean {
  return !hasLoadedFile;
}
